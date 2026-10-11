use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Multipart, Path, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path as StdPath, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

// ==================== Modelos ====================

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
}

#[derive(Debug, Serialize, Deserialize)]
struct Database {
    users: HashMap<String, User>,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    from_id: String,
    to_id: String,
    texto: String,
    timestamp: String,
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

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    nome: String,
    email: String,
    foto: Option<String>,
}

#[derive(Debug, Serialize)]
struct PublicUser {
    id: String,
    nome: String,
    foto: Option<String>,
    status_online: bool,
    ultima_vez_visto: Option<String>,
}

// ==================== Estado global ====================

struct AppState {
    db_path: String,
    // user_id -> sender do WebSocket
    connections: DashMap<String, tokio::sync::mpsc::UnboundedSender<Message>>,
}

impl AppState {
    fn load_db(&self) -> Database {
        if !StdPath::new(&self.db_path).exists() {
            return Database {
                users: HashMap::new(),
                messages: Vec::new(),
            };
        }
        let data = fs::read_to_string(&self.db_path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or(Database {
            users: HashMap::new(),
            messages: Vec::new(),
        })
    }

    fn save_db(&self, db: &Database) {
        let json = serde_json::to_string_pretty(db).unwrap();
        fs::write(&self.db_path, json).unwrap();
    }
}

// ==================== Rotas ====================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {
        db_path: "users.json".to_string(),
        connections: DashMap::new(),
    });

    // Cria pasta de uploads (caso queira salvar arquivos depois)
    let _ = fs::create_dir_all("uploads");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/upload_foto/:user_id", post(upload_foto))
        .route("/users", get(list_users))
        .route("/friends/:user_id", get(get_friends))
        .route("/add_friend/:user_id/:friend_id", post(add_friend))
        .route("/messages/:user_id/:friend_id", get(get_messages))
        .route("/send_message", post(send_message))
        .route("/ws/:user_id", get(ws_handler))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:10000").await.unwrap();

    println!(" [TODO] Servidor rodando em http://0.0.0.0:10000");
    axum::serve(listener, app).await.unwrap();
}

// ==================== Handlers HTTP ====================

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UserCreate>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let mut db = state.load_db();

    // Verifica email duplicado
    if db.users.values().any(|u| u.email == payload.email) {
        return Err((StatusCode::BAD_REQUEST, "Email já cadastrado".into()));
    }

    let user_id = Uuid::new_v4().to_string();
    let hashed = hash(&payload.senha, DEFAULT_COST)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user = User {
        id: user_id.clone(),
        nome: payload.nome.clone(),
        email: payload.email.clone(),
        senha: hashed,
        foto: None,
        amigos: Vec::new(),
        status_online: false,
        ultima_vez_visto: None,
    };

    db.users.insert(user_id.clone(), user);
    state.save_db(&db);

    Ok(Json(UserResponse {
        id: user_id,
        nome: payload.nome,
        email: payload.email,
        foto: None,
    }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UserLogin>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let db = state.load_db();

    for user in db.users.values() {
        if user.email == payload.email {
            if verify(&payload.senha, &user.senha).unwrap_or(false) {
                return Ok(Json(UserResponse {
                    id: user.id.clone(),
                    nome: user.nome.clone(),
                    email: user.email.clone(),
                    foto: user.foto.clone(),
                }));
            }
        }
    }

    Err((StatusCode::UNAUTHORIZED, "Email ou senha incorretos".into()))
}

async fn upload_foto(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut db = state.load_db();

    if !db.users.contains_key(&user_id) {
        return Err((StatusCode::NOT_FOUND, "Usuário não encontrado".into()));
    }

    while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let content_type = field
            .content_type()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "image/jpeg".to_string());

        let data = field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        let b64 = general_purpose::STANDARD.encode(&data);
        let foto = format!("data:{};base64,{}", content_type, b64);

        if let Some(user) = db.users.get_mut(&user_id) {
            user.foto = Some(foto.clone());
        }

        state.save_db(&db);
        return Ok(Json(serde_json::json!({ "foto": foto })));
    }

    Err((StatusCode::BAD_REQUEST, "Nenhum arquivo enviado".into()))
}

async fn list_users(State(state): State<Arc<AppState>>) -> Json<Vec<PublicUser>> {
    let db = state.load_db();
    let users: Vec<PublicUser> = db
        .users
        .values()
        .map(|u| PublicUser {
            id: u.id.clone(),
            nome: u.nome.clone(),
            foto: u.foto.clone(),
            status_online: u.status_online,
            ultima_vez_visto: u.ultima_vez_visto.clone(),
        })
        .collect();
    Json(users)
}

async fn get_friends(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<PublicUser>>, (StatusCode, String)> {
    let db = state.load_db();

    let user = db
            .users
            .get(&user_id)
        .ok_or((StatusCode::NOT_FOUND, "Usuário não encontrado".into()))?;

    let friends: Vec<PublicUser> = user
        .amigos
        .iter()
        .filter_map(|fid| db.users.get(fid))
        .map(|f| PublicUser {
            id: f.id.clone(),
            nome: f.nome.clone(),
            foto: f.foto.clone(),
            status_online: f.status_online,
            ultima_vez_visto: f.ultima_vez_visto.clone(),
        })
        .collect();

    Ok(Json(friends))
}

async fn add_friend(
    State(state): State<Arc<AppState>>,
    Path((user_id, friend_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut db = state.load_db();

    if !db.users.contains_key(&user_id) || !db.users.contains_key(&friend_id) {
        return Err((StatusCode::NOT_FOUND, "Usuário não encontrado".into()));
    }

    if let Some(user) = db.users.get_mut(&user_id) {
        if !user.amigos.contains(&friend_id) {
            user.amigos.push(friend_id.clone());
        }
    }

    // Adiciona reciprocamente
    if let Some(friend) = db.users.get_mut(&friend_id) {
        if !friend.amigos.contains(&user_id) {
            friend.amigos.push(user_id);
        }
    }

    state.save_db(&db);
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    Path((user_id, friend_id)): Path<(String, String)>,
) -> Json<Vec<ChatMessage>> {
    let db = state.load_db();

    let mut msgs: Vec<ChatMessage> = db
        .messages
        .into_iter()
        .filter(|m| {
            (m.from_id == user_id && m.to_id == friend_id)
                || (m.from_id == friend_id && m.to_id == user_id)
        })
        .collect();

    msgs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Json(msgs)
}

async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(msg): Json<ChatMessage>,
) -> Json<serde_json::Value> {
    let mut db = state.load_db();
    db.messages.push(msg.clone());
    state.save_db(&db);

    // Envia via WebSocket se o destinatário estiver online
    if let Some(sender) = state.connections.get(&msg.to_id) {
        let payload = serde_json::json!({
            "type": "message",
            "data": msg
        });
        let _ = sender.send(Message::Text(payload.to_string()));
    }

    Json(serde_json::json!({ "ok": true }))
}

// ==================== WebSocket ====================

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(user_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, user_id, state))
}

async fn handle_socket(socket: WebSocket, user_id: String, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    state.connections.insert(user_id.clone(), tx);

    // ========== Marca como ONLINE ==========
    {
        let mut db = state.load_db();
        if let Some(user) = db.users.get_mut(&user_id) {
            user.status_online = true;
            user.ultima_vez_visto = Some(Utc::now().to_rfc3339());

            // Clona a lista de amigos ANTES de salvar
            let amigos = user.amigos.clone();

            state.save_db(&db); // agora pode salvar

            // Avisa os amigos
            for friend_id in amigos {
                if let Some(friend_tx) = state.connections.get(&friend_id) {
                    let payload = serde_json::json!({
                        "type": "status",
                        "user_id": user_id,
                        "status_online": true
                    });
                    let _ = friend_tx.send(Message::Text(payload.to_string()));
                }
            }
        }
    }

    // Task que envia mensagens do canal para o WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Task que recebe mensagens do cliente
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                if text == "ping" {
                    // opcional
                }
            }
        }
    });

    // Espera qualquer uma das tasks terminar
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    // ========== Marca como OFFLINE ==========
    state.connections.remove(&user_id);

    {
        let mut db = state.load_db();
        if let Some(user) = db.users.get_mut(&user_id) {
            user.status_online = false;
            user.ultima_vez_visto = Some(Utc::now().to_rfc3339());

            // Clona os dados necessários ANTES de salvar
            let amigos = user.amigos.clone();
            let ultima_vez = user.ultima_vez_visto.clone();

            state.save_db(&db); // agora pode salvar

            // Avisa os amigos
            for friend_id in amigos {
                if let Some(friend_tx) = state.connections.get(&friend_id) {
                    let payload = serde_json::json!({
                        "type": "status",
                        "user_id": user_id,
                        "status_online": false,
                        "ultima_vez_visto": ultima_vez
                    });
                    let _ = friend_tx.send(Message::Text(payload.to_string()));
                }
            }
        }
    }

    println!("Usuário {} desconectado", user_id);
}