//! Free Bird server v0.3
//!
//! O servidor é só um CORREIO: guarda mensagens/imagens até o destinatário baixar e
//! confirmar (ack), e então apaga. O histórico fica no celular de cada usuário.
//! Fica no servidor: contas, lista de amigos, fotos de perfil, comunicados e a fila de entrega.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Multipart, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{SecondsFormat, Utc};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message as MailMessage, Tokio1Executor,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};
use uuid::Uuid;

type ApiErr = (StatusCode, String);

const OUTBOX_TTL_DAYS: i64 = 14;
const OUTBOX_MAX: usize = 50_000;

// ==================== Modelos ====================

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    nome: String,
    email: String,
    senha: String,
    foto: Option<String>,
    amigos: Vec<String>,
    status_online: bool,
    ultima_vez_visto: Option<String>,
    #[serde(default = "default_true")]
    email_verificado: bool,
}

/// Mensagem em trânsito. O servidor NÃO guarda histórico.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    id: String,
    #[serde(default)]
    from_id: String,
    to_id: String,
    #[serde(default)]
    texto: String,
    /// "/media/<arquivo>" — apagado do servidor assim que o destinatário confirmar
    #[serde(default)]
    image_url: Option<String>,
    #[serde(default)]
    timestamp: String,
}

/// Item da fila de entrega de um usuário (message, reaction, message_deleted,
/// friend_added, friend_removed, delivered).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Event {
    id: String,
    to_id: String,
    kind: String,
    data: Value,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Notification {
    id: String,
    titulo: String,
    corpo: String,
    timestamp: String,
    para: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Database {
    users: HashMap<String, User>,
    #[serde(default)]
    outbox: Vec<Event>,
    #[serde(default)]
    notifications: Vec<Notification>,
    /// Histórico das versões antigas: preservado no arquivo, mas não é mais servido.
    #[serde(default)]
    messages: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct UserCreate {
    nome: String,
    email: String,
    senha: String,
}

#[derive(Debug, Deserialize)]
struct UserLogin {
    email: String,
    senha: String,
}

#[derive(Debug, Deserialize)]
struct VerifyReq {
    email: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct EmailReq {
    email: String,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    nome: String,
    email: String,
    foto: Option<String>,
    email_verificado: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct PublicUser {
    id: String,
    nome: String,
    foto: Option<String>,
    status_online: bool,
    ultima_vez_visto: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReactReq {
    to_id: String,
    message_id: String,
    /// "" = remover minha reação
    emoji: String,
}

#[derive(Debug, Deserialize)]
struct DeleteMsgReq {
    to_id: String,
    message_id: String,
}

#[derive(Debug, Deserialize)]
struct AckReq {
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AnnounceReq {
    titulo: String,
    corpo: String,
    para: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SinceQuery {
    since: Option<String>,
}

// ==================== Email ====================

struct Mailer {
    /// (api key, email remetente verificado) — envio por HTTPS, funciona no Render free
    brevo: Option<(String, String)>,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: String,
    http: reqwest::Client,
}

impl Mailer {
    /// Ordem: BREVO_API_KEY + MAIL_FROM (HTTPS) > SMTP_USER + SMTP_PASS > só console.
    fn from_env() -> Self {
        let http = reqwest::Client::new();
        if let (Ok(key), Ok(from)) = (std::env::var("BREVO_API_KEY"), std::env::var("MAIL_FROM")) {
            println!("✉ Emails via Brevo (HTTPS), remetente {from}");
            return Mailer { brevo: Some((key, from)), transport: None, from: String::new(), http };
        }
        match (std::env::var("SMTP_USER"), std::env::var("SMTP_PASS")) {
            (Ok(user), Ok(pass)) => {
                println!("✉ Emails via SMTP (Render free bloqueia essas portas!)");
                let transport = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.gmail.com")
                    .expect("relay smtp")
                    .credentials(Credentials::new(user.clone(), pass))
                    .build();
                Mailer { brevo: None, transport: Some(transport), from: user, http }
            }
            _ => {
                println!("⚠ Sem BREVO_API_KEY/MAIL_FROM nem SMTP_USER/SMTP_PASS: os códigos serão impressos no console.");
                Mailer { brevo: None, transport: None, from: String::new(), http }
            }
        }
    }

    async fn send(&self, to: &str, subject: &str, body: String) -> Result<(), String> {
        if let Some((key, sender)) = &self.brevo {
            let resp = self
                .http
                .post("https://api.brevo.com/v3/smtp/email")
                .header("api-key", key)
                .header("accept", "application/json")
                .timeout(Duration::from_secs(15))
                .json(&serde_json::json!({
                    "sender": { "name": "Free Bird", "email": sender },
                    "to": [{ "email": to }],
                    "subject": subject,
                    "textContent": body
                }))
                .send()
                .await
                .map_err(|e| format!("Brevo: {e}"))?;
            if resp.status().is_success() {
                return Ok(());
            }
            let st = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(format!("Brevo {st}: {txt}"));
        }

        let Some(transport) = &self.transport else {
            println!("[DEV] email para {to} | {subject}\n{body}");
            return Ok(());
        };
        let from: Mailbox = format!("Free Bird <{}>", self.from)
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let to: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let email = MailMessage::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .body(body)
            .map_err(|e| e.to_string())?;
        // sem esse limite, uma porta bloqueada deixa o cadastro pendurado até o app desistir
        tokio::time::timeout(Duration::from_secs(15), transport.send(email))
            .await
            .map_err(|_| "tempo esgotado no SMTP (porta bloqueada pelo provedor?)".to_string())?
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ==================== Estado global ====================

struct PendingCode {
    code: String,
    expires: Instant,
    sent_at: Instant,
    attempts: u8,
}

struct AppState {
    db_path: String,
    lock: tokio::sync::Mutex<()>,
    tokens_lock: std::sync::Mutex<()>,
    // user_id -> (id da conexão, sender do WebSocket)
    connections: DashMap<String, (Uuid, tokio::sync::mpsc::UnboundedSender<Message>)>,
    codes: DashMap<String, PendingCode>,
    // token de sessão -> user_id
    tokens: DashMap<String, String>,
    mailer: Mailer,
}

impl AppState {
    fn load_db(&self) -> Database {
        match fs::read_to_string(&self.db_path) {
            Ok(data) if !data.trim().is_empty() => serde_json::from_str(&data)
                .expect("users.json inválido/corrompido: restaure o backup (não vou sobrescrever)"),
            _ => Database::default(),
        }
    }

    fn save_db(&self, db: &Database) {
        let json = serde_json::to_string(db).unwrap();
        let tmp = format!("{}.tmp", self.db_path);
        fs::write(&tmp, json).unwrap();
        fs::rename(&tmp, &self.db_path).unwrap();
    }
}

// ==================== Helpers ====================

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn age_days(ts: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| (Utc::now() - d.with_timezone(&Utc)).num_days())
        .unwrap_or(0)
}

fn bad(msg: &str) -> ApiErr {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

fn internal<E: ToString>(e: E) -> ApiErr {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn valid_email(e: &str) -> bool {
    e.len() <= 254
        && !e.contains(char::is_whitespace)
        && e.split('@').count() == 2
        && e.split('@').all(|p| !p.is_empty())
        && e.rsplit('@').next().map_or(false, |d| d.contains('.'))
}

fn sniff_ext(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else if d.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if d.starts_with(b"GIF8") {
        Some("gif")
    } else if d.len() > 12 && &d[0..4] == b"RIFF" && &d[8..12] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}

fn check_admin(headers: &HeaderMap) -> Result<(), ApiErr> {
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "ADMIN_TOKEN não configurado no servidor".into()));
    }
    let got = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    let same = got.len() == expected.len()
        && got.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    if same {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Token de admin inválido".into()))
    }
}

// ---------- sessão (token) ----------

fn save_tokens(state: &AppState) {
    let _g = state.tokens_lock.lock().unwrap();
    let map: HashMap<String, String> = state
        .tokens
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    let tmp = "tokens.json.tmp";
    fs::write(tmp, serde_json::to_string(&map).unwrap()).unwrap();
    fs::rename(tmp, "tokens.json").unwrap();
}

fn issue_token(state: &AppState, user_id: &str) -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill(&mut b);
    let token: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    state.tokens.insert(token.clone(), user_id.to_string());
    save_tokens(state);
    token
}

/// Header: `Authorization: Bearer <token>` → id do usuário logado.
fn auth_user(state: &AppState, headers: &HeaderMap) -> Result<String, ApiErr> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Faça login novamente".to_string()))?;
    state
        .tokens
        .get(token)
        .map(|u| u.clone())
        .ok_or((StatusCode::UNAUTHORIZED, "Sessão expirada. Faça login novamente.".to_string()))
}

fn require_me(state: &AppState, headers: &HeaderMap, user_id: &str) -> Result<(), ApiErr> {
    let me = auth_user(state, headers)?;
    if me != user_id {
        return Err((StatusCode::FORBIDDEN, "Sem permissão".into()));
    }
    Ok(())
}

fn user_resp(u: &User, token: Option<String>) -> UserResponse {
    UserResponse {
        id: u.id.clone(),
        nome: u.nome.clone(),
        email: u.email.clone(),
        foto: u.foto.clone(),
        email_verificado: u.email_verificado,
        token,
    }
}

// ---------- fila de eventos ----------

fn new_event(to: &str, kind: &str, data: Value) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        to_id: to.to_string(),
        kind: kind.to_string(),
        data,
        timestamp: now_iso(),
    }
}

/// Entrega na hora se o usuário estiver online (o evento continua na fila até o ack).
fn push_event(state: &AppState, ev: &Event) {
    if let Some(c) = state.connections.get(&ev.to_id) {
        let payload = json!({
            "type": "event",
            "id": ev.id,
            "kind": ev.kind,
            "data": ev.data,
            "timestamp": ev.timestamp
        })
        .to_string();
        let _ = c.1.send(Message::Text(payload));
    }
}

fn are_friends(db: &Database, a: &str, b: &str) -> bool {
    db.users
        .get(a)
        .map_or(false, |u| u.amigos.iter().any(|x| x == b))
}

fn event_image_url(e: &Event) -> Option<String> {
    e.data.get("image_url").and_then(|v| v.as_str()).map(|s| s.to_string())
}

// ---------- arquivos ----------

async fn save_image(mut multipart: Multipart, dir: &str) -> Result<String, ApiErr> {
    let field = multipart
        .next_field()
        .await
        .map_err(|e| bad(&e.to_string()))?
        .ok_or_else(|| bad("Nenhum arquivo enviado"))?;
    let data = field.bytes().await.map_err(|e| bad(&e.to_string()))?;

    if data.len() > 8 * 1024 * 1024 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "Imagem maior que 8 MB".into()));
    }
    let ext = sniff_ext(&data).ok_or_else(|| bad("Formato não suportado (use JPG, PNG, WebP ou GIF)"))?;

    let name = format!("{}.{}", Uuid::new_v4(), ext);
    tokio::fs::write(format!("{dir}/{name}"), &data).await.map_err(internal)?;
    Ok(format!("/{dir}/{name}"))
}

async fn remove_upload(url: &str) {
    let (dir, name) = if let Some(n) = url.strip_prefix("/media/") {
        ("media", n)
    } else if let Some(n) = url.strip_prefix("/avatars/") {
        ("avatars", n)
    } else {
        return;
    };
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return;
    }
    let _ = tokio::fs::remove_file(format!("{dir}/{name}")).await;
}

// ---------- presença / códigos ----------

async fn set_presence(state: &Arc<AppState>, user_id: &str, online: bool) {
    let now = now_iso();
    let amigos = {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        let Some(user) = db.users.get_mut(user_id) else { return };
        user.status_online = online;
        user.ultima_vez_visto = Some(now.clone());
        let amigos = user.amigos.clone();
        state.save_db(&db);
        amigos
    };

    let payload = json!({
        "type": "status",
        "user_id": user_id,
        "status_online": online,
        "ultima_vez_visto": now
    })
    .to_string();
    for fid in amigos {
        if let Some(c) = state.connections.get(&fid) {
            let _ = c.1.send(Message::Text(payload.clone()));
        }
    }
}

async fn send_code(state: &Arc<AppState>, email: &str) -> Result<(), ApiErr> {
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    let code = format!("{:06}", n);
    state.codes.insert(
        email.to_string(),
        PendingCode {
            code: code.clone(),
            expires: Instant::now() + Duration::from_secs(600),
            sent_at: Instant::now(),
            attempts: 0,
        },
    );
    let body = format!(
        "Seu código do Free Bird: {code}\n\nVálido por 10 minutos. Se não foi você, ignore este email."
    );
    state
        .mailer
        .send(email, "Seu código de verificação - Free Bird", body)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Não consegui enviar o email: {e}")))
}

// ==================== limpeza periódica ====================

async fn sweeper(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;

        let mut files: Vec<String> = Vec::new();
        {
            let _g = state.lock.lock().await;
            let mut db = state.load_db();
            let before = db.outbox.len();
            let old = std::mem::take(&mut db.outbox);
            let mut kept = Vec::with_capacity(old.len());
            for e in old {
                if age_days(&e.timestamp) >= OUTBOX_TTL_DAYS {
                    if let Some(u) = event_image_url(&e) {
                        files.push(u);
                    }
                } else {
                    kept.push(e);
                }
            }
            db.outbox = kept;
            if db.outbox.len() != before {
                state.save_db(&db);
            }
        }
        for f in files {
            remove_upload(&f).await;
        }

        // uploads que nunca viraram mensagem (mais de 1 dia, fora da fila)
        let referenced: HashSet<String> = state
            .load_db()
            .outbox
            .iter()
            .filter_map(|e| event_image_url(e))
            .filter_map(|u| u.strip_prefix("/media/").map(|s| s.to_string()))
            .collect();
        if let Ok(rd) = fs::read_dir("media") {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let old = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map_or(false, |d| d > Duration::from_secs(86_400));
                if old && !referenced.contains(&name) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

// ==================== main ====================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let tokens = DashMap::new();
    if let Ok(s) = fs::read_to_string("tokens.json") {
        if let Ok(m) = serde_json::from_str::<HashMap<String, String>>(&s) {
            for (k, v) in m {
                tokens.insert(k, v);
            }
        }
    }

    let state = Arc::new(AppState {
        db_path: "users.json".to_string(),
        lock: tokio::sync::Mutex::new(()),
        tokens_lock: std::sync::Mutex::new(()),
        connections: DashMap::new(),
        codes: DashMap::new(),
        tokens,
        mailer: Mailer::from_env(),
    });

    let _ = fs::create_dir_all("avatars");
    let _ = fs::create_dir_all("media");

    tokio::spawn(sweeper(state.clone()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // conta
        .route("/register", post(register))
        .route("/verify_email", post(verify_email))
        .route("/resend_code", post(resend_code))
        .route("/login", post(login))
        .route("/logout", post(logout))
        // perfil / amigos
        .route("/upload_foto/:user_id", post(upload_foto))
        .route("/users", get(list_users))
        .route("/friends/:user_id", get(get_friends))
        .route("/friends/:user_id/:friend_id", delete(remove_friend))
        .route("/add_friend/:user_id/:friend_id", post(add_friend))
        // correio
        .route("/upload_image/:user_id", post(upload_image))
        .route("/send_message", post(send_message))
        .route("/react", post(react))
        .route("/delete_message", post(delete_message))
        .route("/inbox/:user_id", get(inbox))
        .route("/ack/:user_id", post(ack))
        // comunicados
        .route("/notifications/:user_id", get(get_notifications))
        .route("/admin/announce", post(admin_announce))
        .route("/admin/users", get(admin_users))
        // tempo real
        .route("/ws/:user_id", get(ws_handler))
        .nest_service("/avatars", ServeDir::new("avatars"))
        .nest_service("/media", ServeDir::new("media"))
        .nest_service("/uploads", ServeDir::new("uploads")) // compatibilidade v0.2
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024))
        .layer(cors)
        .with_state(state);

    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();

    println!("Servidor rodando em http://{bind}");
    axum::serve(listener, app).await.unwrap();
}

// ==================== Conta / email ====================

async fn register(
    State(state): State<Arc<AppState>>,
    Json(p): Json<UserCreate>,
) -> Result<Json<UserResponse>, ApiErr> {
    let nome = p.nome.trim().to_string();
    let email = p.email.trim().to_lowercase();

    if nome.is_empty() || nome.chars().count() > 40 {
        return Err(bad("Nome deve ter de 1 a 40 caracteres"));
    }
    if !valid_email(&email) {
        return Err(bad("Email inválido"));
    }
    if std::env::var("REQUIRE_GMAIL").map_or(false, |v| v == "1")
        && !(email.ends_with("@gmail.com") || email.ends_with("@googlemail.com"))
    {
        return Err(bad("Use um email @gmail.com"));
    }
    if p.senha.len() < 6 {
        return Err(bad("A senha precisa ter pelo menos 6 caracteres"));
    }

    let senha = p.senha.clone();
    let hashed = tokio::task::spawn_blocking(move || hash(senha, DEFAULT_COST))
        .await
        .map_err(internal)?
        .map_err(internal)?;

    // SKIP_EMAIL_VERIFICATION=1: pula o código (útil para testes). Qualquer email passa.
    let skip = std::env::var("SKIP_EMAIL_VERIFICATION").map_or(false, |v| v == "1");

    let user_id;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();

        let existing = db
            .users
            .values()
            .find(|u| u.email.to_lowercase() == email)
            .map(|u| (u.id.clone(), u.email_verificado));

        match existing {
            Some((_, true)) => return Err(bad("Email já cadastrado")),
            Some((id, false)) => {
                if let Some(u) = db.users.get_mut(&id) {
                    u.nome = nome.clone();
                    u.senha = hashed;
                    if skip {
                        u.email_verificado = true;
                    }
                }
                user_id = id;
            }
            None => {
                user_id = Uuid::new_v4().to_string();
                db.users.insert(
                    user_id.clone(),
                    User {
                        id: user_id.clone(),
                        nome: nome.clone(),
                        email: email.clone(),
                        senha: hashed,
                        foto: None,
                        amigos: Vec::new(),
                        status_online: false,
                        ultima_vez_visto: None,
                        email_verificado: skip,
                    },
                );
            }
        }
        state.save_db(&db);
    }

    if skip {
        // entra direto: o app já trata "verificado + token" como login concluído
        let token = state.new_session(&user_id);
        return Ok(Json(UserResponse {
            id: user_id,
            nome,
            email,
            foto: None,
            email_verificado: true,
            token: Some(token),
        }));
    }

    send_code(&state, &email).await?;

    Ok(Json(UserResponse {
        id: user_id,
        nome,
        email,
        foto: None,
        email_verificado: false,
        token: None,
    }))
}

async fn verify_email(
    State(state): State<Arc<AppState>>,
    Json(p): Json<VerifyReq>,
) -> Result<Json<UserResponse>, ApiErr> {
    let email = p.email.trim().to_lowercase();

    {
        let mut entry = state
            .codes
            .get_mut(&email)
            .ok_or_else(|| bad("Nenhum código pendente. Peça um novo."))?;

        if Instant::now() > entry.expires {
            drop(entry);
            state.codes.remove(&email);
            return Err((StatusCode::GONE, "Código expirado. Peça um novo.".into()));
        }
        entry.attempts += 1;
        if entry.attempts > 5 {
            drop(entry);
            state.codes.remove(&email);
            return Err((StatusCode::TOO_MANY_REQUESTS, "Tentativas demais. Peça um novo código.".into()));
        }
    ///    if entry.code != p.code.trim() {
        //    return Err(bad("Código incorreto"));
     //   }
    }
    state.codes.remove(&email);

    let user = {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        let id = db
            .users
            .values()
            .find(|u| u.email.to_lowercase() == email)
            .map(|u| u.id.clone())
            .ok_or((StatusCode::NOT_FOUND, "Usuário não encontrado".to_string()))?;

        let user = db.users.get_mut(&id).unwrap();
        user.email_verificado = true;
        let copy = user.clone();
        state.save_db(&db);
        copy
    };

    let token = issue_token(&state, &user.id);
    Ok(Json(user_resp(&user, Some(token))))
}

async fn resend_code(
    State(state): State<Arc<AppState>>,
    Json(p): Json<EmailReq>,
) -> Result<Json<Value>, ApiErr> {
    let email = p.email.trim().to_lowercase();

    let too_soon = state
        .codes
        .get(&email)
        .map_or(false, |c| c.sent_at.elapsed() < Duration::from_secs(60));
    if too_soon {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Aguarde 1 minuto para pedir outro código".into()));
    }

    let pending_user = state
        .load_db()
        .users
        .values()
        .any(|u| u.email.to_lowercase() == email && !u.email_verificado);

    if pending_user {
        send_code(&state, &email).await?;
    }
    Ok(Json(json!({ "ok": true })))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(p): Json<UserLogin>,
) -> Result<Json<UserResponse>, ApiErr> {
    let email = p.email.trim().to_lowercase();
    let wrong = || (StatusCode::UNAUTHORIZED, "Email ou senha incorretos".to_string());

    let user = state
        .load_db()
        .users
        .values()
        .find(|u| u.email.to_lowercase() == email)
        .cloned()
        .ok_or_else(wrong)?;

    let hashed = user.senha.clone();
    let senha = p.senha.clone();
    let ok = tokio::task::spawn_blocking(move || verify(senha, &hashed).unwrap_or(false))
        .await
        .unwrap_or(false);
    if !ok {
        return Err(wrong());
    }
    if !user.email_verificado {
        return Err((StatusCode::FORBIDDEN, "EMAIL_NAO_VERIFICADO".into()));
    }

    let token = issue_token(&state, &user.id);
    Ok(Json(user_resp(&user, Some(token))))
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<Value> {
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if state.tokens.remove(token).is_some() {
            save_tokens(&state);
        }
    }
    Json(json!({ "ok": true }))
}

// ==================== Perfil / amigos ====================

async fn upload_foto(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<Value>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    let url = save_image(multipart, "avatars").await?;

    let old = {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        let old = db.users.get_mut(&user_id).and_then(|u| u.foto.replace(url.clone()));
        state.save_db(&db);
        old
    };
    if let Some(o) = old {
        remove_upload(&o).await;
    }
    Ok(Json(json!({ "foto": url })))
}

fn to_public(u: &User) -> PublicUser {
    PublicUser {
        id: u.id.clone(),
        nome: u.nome.clone(),
        foto: u.foto.clone(),
        status_online: u.status_online,
        ultima_vez_visto: u.ultima_vez_visto.clone(),
    }
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PublicUser>>, ApiErr> {
    auth_user(&state, &headers)?;
    let db = state.load_db();
    Ok(Json(
        db.users.values().filter(|u| u.email_verificado).map(to_public).collect(),
    ))
}

async fn get_friends(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<PublicUser>>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    let db = state.load_db();
    let user = db
        .users
        .get(&user_id)
        .ok_or((StatusCode::NOT_FOUND, "Usuário não encontrado".to_string()))?;

    let friends = user
        .amigos
        .iter()
        .filter_map(|fid| db.users.get(fid))
        .map(to_public)
        .collect();
    Ok(Json(friends))
}

async fn add_friend(
    State(state): State<Arc<AppState>>,
    Path((user_id, friend_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    if user_id == friend_id {
        return Err(bad("Você não pode adicionar a si mesmo"));
    }

    let mut ev: Option<Event> = None;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();

        if !db.users.contains_key(&user_id) || !db.users.contains_key(&friend_id) {
            return Err((StatusCode::NOT_FOUND, "Usuário não encontrado".into()));
        }
        if let Some(user) = db.users.get_mut(&user_id) {
            if !user.amigos.contains(&friend_id) {
                user.amigos.push(friend_id.clone());
            }
        }
        if let Some(friend) = db.users.get_mut(&friend_id) {
            if !friend.amigos.contains(&user_id) {
                friend.amigos.push(user_id.clone());
                let e = new_event(&friend_id, "friend_added", json!({ "from_id": user_id }));
                db.outbox.push(e.clone());
                ev = Some(e);
            }
        }
        state.save_db(&db);
    }
    if let Some(e) = ev {
        push_event(&state, &e);
    }
    Ok(Json(json!({ "ok": true })))
}

async fn remove_friend(
    State(state): State<Arc<AppState>>,
    Path((user_id, friend_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    require_me(&state, &headers, &user_id)?;

    let ev;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();

        let user = db
            .users
            .get_mut(&user_id)
            .ok_or((StatusCode::NOT_FOUND, "Usuário não encontrado".to_string()))?;
        user.amigos.retain(|a| a != &friend_id);

        if let Some(friend) = db.users.get_mut(&friend_id) {
            friend.amigos.retain(|a| a != &user_id);
        }
        let e = new_event(&friend_id, "friend_removed", json!({ "from_id": user_id }));
        db.outbox.push(e.clone());
        ev = e;
        state.save_db(&db);
    }
    push_event(&state, &ev);
    Ok(Json(json!({ "ok": true })))
}

// ==================== Correio ====================

/// Sobe a imagem de uma mensagem. Fica no servidor só até o amigo baixar e confirmar.
async fn upload_image(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<Value>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    let url = save_image(multipart, "media").await?;
    Ok(Json(json!({ "url": url })))
}

async fn send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut msg): Json<ChatMessage>,
) -> Result<Json<ChatMessage>, ApiErr> {
    let me = auth_user(&state, &headers)?;
    msg.from_id = me; // nunca confia no remetente enviado pelo cliente
    msg.texto = msg.texto.trim().to_string();

    if msg.id.is_empty() {
        msg.id = Uuid::new_v4().to_string();
    } else if msg.id.len() > 64 {
        return Err(bad("id inválido"));
    }
    if msg.texto.is_empty() && msg.image_url.is_none() {
        return Err(bad("Mensagem vazia"));
    }
    if msg.texto.chars().count() > 4000 {
        return Err(bad("Mensagem muito longa (máx. 4000 caracteres)"));
    }
    if let Some(u) = &msg.image_url {
        if !u.starts_with("/media/") || u.contains("..") || u[7..].contains('/') {
            return Err(bad("image_url inválida"));
        }
    }
    msg.timestamp = now_iso();

    let ev;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();

        if !db.users.contains_key(&msg.to_id) {
            return Err((StatusCode::NOT_FOUND, "Destinatário não encontrado".into()));
        }
        if !are_friends(&db, &msg.from_id, &msg.to_id) {
            return Err((StatusCode::FORBIDDEN, "Vocês não são amigos".into()));
        }

        // reenvio do mesmo id (retry do app): devolve o que já está na fila
        let dup = db
            .outbox
            .iter()
            .find(|e| {
                e.kind == "message"
                    && e.to_id == msg.to_id
                    && e.data.get("id").and_then(|v| v.as_str()) == Some(msg.id.as_str())
            })
            .and_then(|e| serde_json::from_value::<ChatMessage>(e.data.clone()).ok());
        if let Some(old) = dup {
            return Ok(Json(old));
        }
        if db.outbox.len() >= OUTBOX_MAX {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Fila de entrega cheia, tente mais tarde".into()));
        }

        let e = new_event(&msg.to_id, "message", serde_json::to_value(&msg).unwrap());
        db.outbox.push(e.clone());
        state.save_db(&db);
        ev = e;
    }

    push_event(&state, &ev);
    Ok(Json(msg))
}

async fn react(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ReactReq>,
) -> Result<Json<Value>, ApiErr> {
    let me = auth_user(&state, &headers)?;
    if req.message_id.is_empty() || req.message_id.len() > 64 || req.emoji.len() > 32 {
        return Err(bad("Reação inválida"));
    }

    let ev;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        if !are_friends(&db, &me, &req.to_id) {
            return Err((StatusCode::FORBIDDEN, "Vocês não são amigos".into()));
        }
        let e = new_event(
            &req.to_id,
            "reaction",
            json!({ "message_id": req.message_id, "from_id": me, "emoji": req.emoji }),
        );
        db.outbox.push(e.clone());
        state.save_db(&db);
        ev = e;
    }
    push_event(&state, &ev);
    Ok(Json(json!({ "ok": true })))
}

/// "Excluir para todos". Se o amigo ainda não baixou, a mensagem some da fila e ele nunca a vê.
async fn delete_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeleteMsgReq>,
) -> Result<Json<Value>, ApiErr> {
    let me = auth_user(&state, &headers)?;

    let mut files: Vec<String> = Vec::new();
    let mut ev: Option<Event> = None;
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();

        let old = std::mem::take(&mut db.outbox);
        let mut kept = Vec::with_capacity(old.len());
        let mut removed_pending = false;
        for e in old {
            let is_target = e.kind == "message"
                && e.to_id == req.to_id
                && e.data.get("id").and_then(|v| v.as_str()) == Some(req.message_id.as_str())
                && e.data.get("from_id").and_then(|v| v.as_str()) == Some(me.as_str());
            if is_target {
                removed_pending = true;
                if let Some(u) = event_image_url(&e) {
                    files.push(u);
                }
            } else {
                kept.push(e);
            }
        }
        db.outbox = kept;

        if !removed_pending {
            let e = new_event(
                &req.to_id,
                "message_deleted",
                json!({ "message_id": req.message_id, "from_id": me }),
            );
            db.outbox.push(e.clone());
            ev = Some(e);
        }
        state.save_db(&db);
    }

    for f in files {
        remove_upload(&f).await;
    }
    if let Some(e) = ev {
        push_event(&state, &e);
    }
    Ok(Json(json!({ "ok": true })))
}

async fn inbox(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<Event>>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    let db = state.load_db();
    let mut list: Vec<Event> = db.outbox.into_iter().filter(|e| e.to_id == user_id).collect();
    list.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(Json(list))
}

/// O app confirma que já salvou os eventos. Mensagens são apagadas daqui (e a imagem do disco)
/// e o remetente recebe o aviso "entregue".
async fn ack(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AckReq>,
) -> Result<Json<Value>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    if req.ids.len() > 500 {
        return Err(bad("Máximo de 500 ids por ack"));
    }

    let mut delivered: Vec<Event> = Vec::new();
    let mut files: Vec<String> = Vec::new();
    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        let ids: HashSet<&str> = req.ids.iter().map(|s| s.as_str()).collect();

        let old = std::mem::take(&mut db.outbox);
        let mut kept = Vec::with_capacity(old.len());
        for e in old {
            if e.to_id == user_id && ids.contains(e.id.as_str()) {
                if e.kind == "message" {
                    if let Some(u) = event_image_url(&e) {
                        files.push(u);
                    }
                    let mid = e.data.get("id").and_then(|v| v.as_str());
                    let from = e.data.get("from_id").and_then(|v| v.as_str());
                    if let (Some(mid), Some(from)) = (mid, from) {
                        delivered.push(new_event(
                            from,
                            "delivered",
                            json!({ "message_id": mid, "from_id": user_id }),
                        ));
                    }
                }
            } else {
                kept.push(e);
            }
        }
        kept.extend(delivered.iter().cloned());
        db.outbox = kept;
        state.save_db(&db);
    }

    for f in files {
        remove_upload(&f).await;
    }
    for e in &delivered {
        push_event(&state, e);
    }
    Ok(Json(json!({ "ok": true })))
}

// ==================== Comunicados ====================

async fn get_notifications(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<SinceQuery>,
) -> Result<Json<Vec<Notification>>, ApiErr> {
    require_me(&state, &headers, &user_id)?;
    let db = state.load_db();
    let since = q.since.unwrap_or_default();
    let list = db
        .notifications
        .into_iter()
        .filter(|n| n.para.is_none() || n.para.as_deref() == Some(user_id.as_str()))
        .filter(|n| n.timestamp > since)
        .collect();
    Ok(Json(list))
}

async fn admin_announce(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AnnounceReq>,
) -> Result<Json<Value>, ApiErr> {
    check_admin(&headers)?;

    let titulo = req.titulo.trim().to_string();
    let corpo = req.corpo.trim().to_string();
    if titulo.is_empty() || titulo.chars().count() > 100 {
        return Err(bad("Título deve ter de 1 a 100 caracteres"));
    }
    if corpo.is_empty() || corpo.chars().count() > 2000 {
        return Err(bad("Texto deve ter de 1 a 2000 caracteres"));
    }

    let n = Notification {
        id: Uuid::new_v4().to_string(),
        titulo,
        corpo,
        timestamp: now_iso(),
        para: req.para,
    };

    {
        let _g = state.lock.lock().await;
        let mut db = state.load_db();
        if let Some(uid) = &n.para {
            if !db.users.contains_key(uid) {
                return Err((StatusCode::NOT_FOUND, "Usuário de destino não encontrado".into()));
            }
        }
        db.notifications.push(n.clone());
        let excess = db.notifications.len().saturating_sub(200);
        db.notifications.drain(0..excess);
        state.save_db(&db);
    }

    let payload = json!({ "type": "announcement", "data": n }).to_string();
    let mut entregues = 0;
    match &n.para {
        Some(uid) => {
            if let Some(c) = state.connections.get(uid) {
                if c.1.send(Message::Text(payload)).is_ok() {
                    entregues += 1;
                }
            }
        }
        None => {
            for c in state.connections.iter() {
                if c.value().1.send(Message::Text(payload.clone())).is_ok() {
                    entregues += 1;
                }
            }
        }
    }

    Ok(Json(json!({ "ok": true, "id": n.id, "entregues_agora": entregues })))
}

async fn admin_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiErr> {
    check_admin(&headers)?;
    let db = state.load_db();
    let list: Vec<Value> = db
        .users
        .values()
        .map(|u| {
            json!({
                "id": u.id,
                "nome": u.nome,
                "email": u.email,
                "email_verificado": u.email_verificado,
                "online": u.status_online,
                "ultima_vez_visto": u.ultima_vez_visto,
            })
        })
        .collect();
    Ok(Json(json!({
        "usuarios": list,
        "fila_de_entrega": db.outbox.len(),
    })))
}

// ==================== WebSocket ====================

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Err(e) = require_me(&state, &headers, &user_id) {
        return e.into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, user_id, state))
}

async fn handle_socket(socket: WebSocket, user_id: String, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let conn_id = Uuid::new_v4();
    state.connections.insert(user_id.clone(), (conn_id, tx));

    set_presence(&state, &user_id, true).await;

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // O único que o cliente envia por aqui é "digitando...": {"type":"typing","to":"<id>"}
    let st = state.clone();
    let uid = user_id.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                if v["type"] != "typing" {
                    continue;
                }
                let Some(to) = v["to"].as_str() else { continue };
                if !are_friends(&st.load_db(), &uid, to) {
                    continue;
                }
                if let Some(c) = st.connections.get(to) {
                    let payload = json!({ "type": "typing", "from_id": uid }).to_string();
                    let _ = c.1.send(Message::Text(payload));
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    let removed = state
        .connections
        .remove_if(&user_id, |_, v| v.0 == conn_id)
        .is_some();
    if removed {
        set_presence(&state, &user_id, false).await;
    }

    println!("Usuário {} desconectado", user_id);
}
