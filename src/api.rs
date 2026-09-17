use std::path::{Path, PathBuf};
use std::sync::Arc;

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::db::{Grant, User};
use crate::fsops;
use crate::pty;
use crate::AppState;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (status, Json(ErrorBody { error: msg.into() }))
}

type ApiError = (StatusCode, Json<ErrorBody>);

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "password hash failed"))
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn new_id(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4().simple())
}

fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

fn auth(state: &AppState, headers: &HeaderMap) -> Result<User, ApiError> {
    let token = bearer(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in"))?;
    state
        .db
        .session_user(&token)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in"))
}

fn admin(user: &User) -> Result<(), ApiError> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "admin only"))
    }
}

fn grant_for(state: &AppState, user: &User, sandbox_id: &str) -> Result<Grant, ApiError> {
    if user.role == "admin" {
        return Ok(Grant {
            user_id: user.id.clone(),
            sandbox_id: sandbox_id.to_string(),
            can_read: true,
            can_write: true,
            can_shell: true,
            can_admin: true,
        });
    }
    state
        .db
        .grant(&user.id, sandbox_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .filter(|g| g.can_read || g.can_write || g.can_shell || g.can_admin)
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "no access to this sandbox"))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/works.json", get(well_known))
        .route("/health", get(health))
        .route("/v1/setup", post(setup))
        .route("/v1/login", post(login))
        .route("/v1/logout", post(logout))
        .route("/v1/me", get(me))
        .route("/v1/users", get(users).post(create_user))
        .route("/v1/users/:id", patch(patch_user).delete(delete_user))
        .route("/v1/sandboxes", get(sandboxes).post(create_sandbox))
        .route("/v1/sandboxes/:id", patch(patch_sandbox).delete(delete_sandbox))
        .route("/v1/grants", get(grants).put(put_grant))
        .route("/v1/grants/:user_id/:sandbox_id", delete(delete_grant))
        .route("/v1/sandboxes/:id/tree", get(tree))
        .route("/v1/sandboxes/:id/file", get(get_file).put(put_file).delete(del_file))
        .route("/v1/term/:id", get(term_ws))
}

#[derive(Serialize)]
struct WellKnown {
    name: String,
    product: &'static str,
    api: &'static str,
    auth: &'static str,
    setup_required: bool,
    personal: bool,
}

async fn well_known(State(state): State<AppState>) -> Json<WellKnown> {
    let n = state.db.user_count().unwrap_or(0);
    Json(WellKnown {
        name: state.org_name.clone(),
        product: "works",
        api: "/v1",
        auth: "bearer",
        setup_required: n == 0,
        personal: state.personal,
    })
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct SetupBody {
    org: Option<String>,
    username: String,
    password: String,
    display_name: Option<String>,
}

#[derive(Serialize)]
struct SessionBody {
    token: String,
    user: User,
}

async fn setup(State(state): State<AppState>, Json(body): Json<SetupBody>) -> Result<Json<SessionBody>, ApiError> {
    if state.db.user_count().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))? > 0 {
        return Err(err(StatusCode::CONFLICT, "already set up"));
    }
    if body.username.trim().len() < 2 || body.password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "username or password too short"));
    }
    let id = new_id("user");
    let hash = hash_password(&body.password)?;
    let display = body.display_name.unwrap_or_else(|| body.username.clone());
    state
        .db
        .insert_user(&id, body.username.trim(), &display, &hash, "admin")
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if let Some(org) = body.org {
        let _ = org;
    }
    if state.personal {
        ensure_personal_sandbox(&state, &id)?;
    }
    issue(&state, &User {
        id,
        username: body.username.trim().to_string(),
        display_name: display,
        role: "admin".into(),
    })
}

fn ensure_personal_sandbox(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    if state.db.sandboxes().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?.is_empty() {
        let id = new_id("box");
        let path = state.data_dir.join("desk");
        std::fs::create_dir_all(&path).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .db
            .insert_sandbox(&id, "Desk", &path.to_string_lossy(), "Personal desk")
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        state
            .db
            .put_grant(&Grant {
                user_id: user_id.to_string(),
                sandbox_id: id,
                can_read: true,
                can_write: true,
                can_shell: true,
                can_admin: true,
            })
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    }
    Ok(())
}

fn issue(state: &AppState, user: &User) -> Result<Json<SessionBody>, ApiError> {
    let token = new_token();
    state
        .db
        .put_session(&token, &user.id, 60 * 60 * 24 * 14)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(SessionBody {
        token,
        user: user.clone(),
    }))
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> Result<Json<SessionBody>, ApiError> {
    let row = state
        .db
        .user_by_username(body.username.trim())
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid username or password"))?;
    if !verify_password(&body.password, &row.1) {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid username or password"));
    }
    issue(&state, &row.0)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    if let Some(token) = bearer(&headers) {
        let _ = state.db.delete_session(&token);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct MeBody {
    user: User,
    sandboxes: Vec<crate::db::Sandbox>,
    default_sandbox_id: Option<String>,
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<MeBody>, ApiError> {
    let user = auth(&state, &headers)?;
    let all = state.db.sandboxes().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let grants = state.db.grants().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let sandboxes = if user.role == "admin" {
        all
    } else {
        let allowed: Vec<_> = grants
            .iter()
            .filter(|g| g.user_id == user.id && (g.can_read || g.can_write || g.can_shell))
            .map(|g| g.sandbox_id.clone())
            .collect();
        all.into_iter().filter(|s| allowed.iter().any(|id| id == &s.id)).collect()
    };
    let default_sandbox_id = sandboxes.first().map(|s| s.id.clone());
    Ok(Json(MeBody {
        user,
        sandboxes,
        default_sandbox_id,
    }))
}

async fn users(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<User>>, ApiError> {
    let user = auth(&state, &headers)?;
    admin(&user)?;
    state.db.users().map(Json).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    display_name: Option<String>,
    role: Option<String>,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewUser>,
) -> Result<Json<User>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    if body.username.trim().len() < 2 || body.password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "username or password too short"));
    }
    let role = match body.role.as_deref().unwrap_or("member") {
        "admin" => "admin",
        _ => "member",
    };
    let id = new_id("user");
    let hash = hash_password(&body.password)?;
    let display = body.display_name.unwrap_or_else(|| body.username.clone());
    state
        .db
        .insert_user(&id, body.username.trim(), &display, &hash, role)
        .map_err(|e| err(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(User {
        id,
        username: body.username.trim().to_string(),
        display_name: display,
        role: role.into(),
    }))
}

#[derive(Deserialize)]
struct PatchUser {
    display_name: Option<String>,
    role: Option<String>,
    password: Option<String>,
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Json(body): Json<PatchUser>,
) -> Result<Json<User>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    let hash = if let Some(p) = body.password.as_ref() {
        if p.len() < 8 {
            return Err(err(StatusCode::BAD_REQUEST, "password too short"));
        }
        Some(hash_password(p)?)
    } else {
        None
    };
    let role = body.role.as_deref();
    if let Some(r) = role {
        if r != "admin" && r != "member" {
            return Err(err(StatusCode::BAD_REQUEST, "role must be admin or member"));
        }
    }
    state
        .db
        .update_user(&id, body.display_name.as_deref(), role, hash.as_deref())
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    state
        .db
        .user_by_id(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Result<StatusCode, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    if actor.id == id {
        return Err(err(StatusCode::BAD_REQUEST, "cannot delete yourself"));
    }
    state.db.delete_user(&id).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sandboxes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::db::Sandbox>>, ApiError> {
    let me = me(State(state), headers).await?;
    Ok(Json(me.0.sandboxes))
}

#[derive(Deserialize)]
struct NewSandbox {
    name: String,
    path: String,
    description: Option<String>,
}

async fn create_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewSandbox>,
) -> Result<Json<crate::db::Sandbox>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    let path = PathBuf::from(body.path.trim());
    if !path.is_absolute() {
        return Err(err(StatusCode::BAD_REQUEST, "sandbox path must be absolute"));
    }
    std::fs::create_dir_all(&path).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let id = new_id("box");
    let desc = body.description.unwrap_or_default();
    state
        .db
        .insert_sandbox(&id, body.name.trim(), &path.to_string_lossy(), &desc)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(crate::db::Sandbox {
        id,
        name: body.name.trim().to_string(),
        path: path.to_string_lossy().into_owned(),
        description: desc,
    }))
}

#[derive(Deserialize)]
struct PatchSandbox {
    name: Option<String>,
    path: Option<String>,
    description: Option<String>,
}

async fn patch_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Json(body): Json<PatchSandbox>,
) -> Result<Json<crate::db::Sandbox>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    if let Some(p) = body.path.as_ref() {
        let path = PathBuf::from(p);
        if !path.is_absolute() {
            return Err(err(StatusCode::BAD_REQUEST, "sandbox path must be absolute"));
        }
        std::fs::create_dir_all(&path).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    state
        .db
        .update_sandbox(&id, body.name.as_deref(), body.path.as_deref(), body.description.as_deref())
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))
}

async fn delete_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Result<StatusCode, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    state.db.delete_sandbox(&id).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn grants(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<Grant>>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    state.db.grants().map(Json).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))
}

#[derive(Deserialize)]
struct GrantBody {
    user_id: String,
    sandbox_id: String,
    can_read: bool,
    can_write: bool,
    can_shell: bool,
    can_admin: Option<bool>,
}

async fn put_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GrantBody>,
) -> Result<Json<Grant>, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    let g = Grant {
        user_id: body.user_id,
        sandbox_id: body.sandbox_id,
        can_read: body.can_read,
        can_write: body.can_write,
        can_shell: body.can_shell,
        can_admin: body.can_admin.unwrap_or(false),
    };
    state.db.put_grant(&g).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(g))
}

async fn delete_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath((user_id, sandbox_id)): AxPath<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let actor = auth(&state, &headers)?;
    admin(&actor)?;
    state
        .db
        .delete_grant(&user_id, &sandbox_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Result<Json<Vec<fsops::TreeEntry>>, ApiError> {
    let user = auth(&state, &headers)?;
    let g = grant_for(&state, &user, &id)?;
    if !g.can_read && !g.can_write {
        return Err(err(StatusCode::FORBIDDEN, "no file access"));
    }
    let box_ = state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))?;
    fsops::list_tree(Path::new(&box_.path))
        .map(Json)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))
}

#[derive(Deserialize)]
struct FileQ {
    path: String,
}

async fn get_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Query(q): Query<FileQ>,
) -> Result<Vec<u8>, ApiError> {
    let user = auth(&state, &headers)?;
    let g = grant_for(&state, &user, &id)?;
    if !g.can_read && !g.can_write {
        return Err(err(StatusCode::FORBIDDEN, "no file access"));
    }
    let box_ = state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))?;
    fsops::read_file(Path::new(&box_.path), &q.path).map_err(|e| err(StatusCode::NOT_FOUND, e))
}

#[derive(Deserialize)]
struct FilePut {
    path: String,
    content: Option<String>,
    b64: Option<String>,
}

async fn put_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Json(body): Json<FilePut>,
) -> Result<StatusCode, ApiError> {
    let user = auth(&state, &headers)?;
    let g = grant_for(&state, &user, &id)?;
    if !g.can_write {
        return Err(err(StatusCode::FORBIDDEN, "read only"));
    }
    let box_ = state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))?;
    let bytes = if let Some(b64) = body.b64 {
        pty::b64_decode(&b64).map_err(|e| err(StatusCode::BAD_REQUEST, e))?
    } else {
        body.content.unwrap_or_default().into_bytes()
    };
    fsops::write_file(Path::new(&box_.path), &body.path, &bytes).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn del_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Query(q): Query<FileQ>,
) -> Result<StatusCode, ApiError> {
    let user = auth(&state, &headers)?;
    let g = grant_for(&state, &user, &id)?;
    if !g.can_write {
        return Err(err(StatusCode::FORBIDDEN, "read only"));
    }
    let box_ = state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))?;
    fsops::remove_path(Path::new(&box_.path), &q.path).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct TermQ {
    token: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
    cwd: Option<String>,
}

async fn term_ws(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
    Query(q): Query<TermQ>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let token = q
        .token
        .or_else(|| bearer(&headers))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in"))?;
    let user = state
        .db
        .session_user(&token)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in"))?;
    let g = grant_for(&state, &user, &id)?;
    if !g.can_shell {
        return Err(err(StatusCode::FORBIDDEN, "no shell on this sandbox"));
    }
    let box_ = state
        .db
        .sandbox(&id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such sandbox"))?;
    let root = PathBuf::from(&box_.path);
    let cwd = if let Some(rel) = q.cwd.filter(|s| !s.is_empty()) {
        fsops::join_rel(&root, &rel).map_err(|e| err(StatusCode::BAD_REQUEST, e))?
    } else {
        root.clone()
    };
    let cols = q.cols.unwrap_or(80);
    let rows = q.rows.unwrap_or(24);
    let sid = new_id("term");
    Ok(ws.on_upgrade(move |socket| term_session(state, socket, sid, root, cwd, cols, rows)))
}

async fn term_session(state: AppState, mut socket: WebSocket, sid: String, root: PathBuf, cwd: PathBuf, cols: u16, rows: u16) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let sid2 = sid.clone();
    let hub = Arc::clone(&state.pty);
    let opened = hub.open(
        sid.clone(),
        root,
        cwd.clone(),
        cols,
        rows,
        move |bytes| {
            let _ = tx.send(bytes);
        },
        {
            let sid = sid2.clone();
            let hub = Arc::clone(&hub);
            move || {
                hub.close(&sid);
            }
        },
    );
    let (shell, cwd_s) = match opened {
        Ok(v) => v,
        Err(e) => {
            let _ = socket
                .send(Message::Text(
                    serde_json::json!({ "type": "error", "error": e }).to_string(),
                ))
                .await;
            return;
        }
    };
    let info = serde_json::json!({
        "type": "info",
        "cwd": cwd_s,
        "shell": shell,
        "os": std::env::consts::OS,
    });
    if socket.send(Message::Text(info.to_string())).await.is_err() {
        state.pty.close(&sid);
        return;
    }
    loop {
        tokio::select! {
            Some(bytes) = rx.recv() => {
                let msg = serde_json::json!({ "type": "output", "data": pty::b64(&bytes) });
                if socket.send(Message::Text(msg.to_string())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(t))) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                            match v.get("type").and_then(|x| x.as_str()) {
                                Some("input") => {
                                    if let Some(data) = v.get("data").and_then(|x| x.as_str()) {
                                        let bytes = if v.get("b64").and_then(|x| x.as_bool()).unwrap_or(false) {
                                            pty::b64_decode(data).unwrap_or_default()
                                        } else {
                                            data.as_bytes().to_vec()
                                        };
                                        let _ = state.pty.write(&sid, &bytes);
                                    }
                                }
                                Some("resize") => {
                                    let cols = v.get("cols").and_then(|x| x.as_u64()).unwrap_or(80) as u16;
                                    let rows = v.get("rows").and_then(|x| x.as_u64()).unwrap_or(24) as u16;
                                    let _ = state.pty.resize(&sid, cols, rows);
                                }
                                Some("close") => break,
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Binary(b))) => {
                        let _ = state.pty.write(&sid, &b);
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
    state.pty.close(&sid);
}
