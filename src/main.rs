mod api;
mod db;
mod fsops;
mod pty;
mod ui;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::db::{Db, Grant};
use crate::pty::PtyHub;

fn bootstrap_admin(db: &Db, data: &PathBuf, username: &str, password: &str, personal: bool) -> Result<(), String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();
    let id = format!("user_{}", uuid::Uuid::new_v4().simple());
    db.insert_user(&id, username, username, &hash, "admin")
        .map_err(|e| e.to_string())?;
    if personal {
        let box_id = format!("box_{}", uuid::Uuid::new_v4().simple());
        let path = data.join("desk");
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        db.insert_sandbox(&box_id, "Desk", &path.to_string_lossy(), "Personal desk")
            .map_err(|e| e.to_string())?;
        db.put_grant(&Grant {
            user_id: id,
            sandbox_id: box_id,
            can_read: true,
            can_write: true,
            can_shell: true,
            can_admin: true,
        })
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub pty: Arc<PtyHub>,
    pub data_dir: PathBuf,
    pub org_name: String,
    pub personal: bool,
    pub ui_origin: Option<String>,
    pub ui_client: Option<reqwest::Client>,
}

#[derive(Parser, Debug)]
#[command(name = "works-server", about = "Desk server for Scalattice Works")]
struct Args {
    /// Listen address
    #[arg(long, env = "WORKS_BIND", default_value = "0.0.0.0:8787")]
    bind: String,
    /// Data directory (sqlite + default personal desk)
    #[arg(long, env = "WORKS_DATA")]
    data: Option<PathBuf>,
    /// Display name returned in /.well-known/works.json
    #[arg(long, env = "WORKS_NAME", default_value = "Works")]
    name: String,
    /// Personal mode: bind can be localhost; creates a desk sandbox under the data dir
    #[arg(long, env = "WORKS_PERSONAL")]
    personal: bool,
    /// Create this admin if the database is empty
    #[arg(long, env = "WORKS_BOOTSTRAP_USER")]
    bootstrap_user: Option<String>,
    /// Password for --bootstrap-user
    #[arg(long, env = "WORKS_BOOTSTRAP_PASSWORD")]
    bootstrap_password: Option<String>,
    /// Extra CORS origins, comma-separated
    #[arg(long, env = "WORKS_CORS", default_value = "")]
    cors: String,
    /// Origin of the hosted SPA to proxy (same origin as this API in the browser)
    #[arg(long, env = "WORKS_UI_ORIGIN", default_value = "https://works.scalattice.com")]
    ui_origin: String,
    /// Do not proxy the UI; API routes only
    #[arg(long, env = "WORKS_API_ONLY")]
    api_only: bool,
}

fn data_dir(personal: bool, override_path: Option<PathBuf>) -> PathBuf {
    if let Some(p) = override_path {
        return p;
    }
    if personal {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/scalattice-works");
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(profile).join("AppData/Local/ScalatticeWorks");
        }
    }
    PathBuf::from("/var/lib/scalattice-works")
}

fn legacy_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/works"));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        dirs.push(PathBuf::from(profile).join("AppData/Local/Works"));
    }
    dirs.push(PathBuf::from("/var/lib/works"));
    dirs
}

fn adopt_legacy_data_dir(dest: &Path) {
    if dest.join("works.sqlite").exists() {
        return;
    }
    for old in legacy_data_dirs() {
        if old == dest || !old.exists() {
            continue;
        }
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::rename(&old, dest).is_ok() {
            tracing::info!(from = %old.display(), to = %dest.display(), "moved data dir");
            return;
        }
    }
}

fn rewrite_legacy_sandbox_paths(db: &Db, dest: &Path) {
    let Ok(boxes) = db.sandboxes() else { return };
    let dest_s = dest.to_string_lossy();
    for box_ in boxes {
        for old in legacy_data_dirs() {
            let old_s = old.to_string_lossy();
            if box_.path == old_s || box_.path.starts_with(&format!("{old_s}/")) {
                let rest = &box_.path[old_s.len()..];
                let next = format!("{dest_s}{rest}");
                if db.update_sandbox(&box_.id, None, Some(&next), None).is_ok() {
                    tracing::info!(id = %box_.id, path = %next, "updated sandbox path");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "works_server=info,tower_http=info".into()))
        .init();

    let args = Args::parse();
    let custom_data = args.data.is_some();
    let data = data_dir(args.personal, args.data);
    if !custom_data {
        adopt_legacy_data_dir(&data);
    }
    std::fs::create_dir_all(&data).expect("data dir");
    let db = Db::open(&data.join("works.sqlite")).expect("sqlite");
    if !custom_data {
        rewrite_legacy_sandbox_paths(&db, &data);
    }
    if let (Some(user), Some(pass)) = (args.bootstrap_user.as_deref(), args.bootstrap_password.as_deref()) {
        if db.user_count().unwrap_or(0) == 0 {
            if let Err(e) = bootstrap_admin(&db, &data, user, pass, args.personal) {
                tracing::error!("bootstrap: {e}");
            }
        }
    }
    let serve_ui = !args.api_only && !args.ui_origin.is_empty();
    let ui_client = if serve_ui {
        Some(
            reqwest::Client::builder()
                .user_agent("works-server-ui")
                .build()
                .expect("ui client"),
        )
    } else {
        None
    };
    let state = AppState {
        db: Arc::new(db),
        pty: Arc::new(PtyHub::default()),
        data_dir: data.clone(),
        org_name: args.name,
        personal: args.personal,
        ui_origin: serve_ui.then_some(args.ui_origin.trim_end_matches('/').to_string()),
        ui_client,
    };

    let mut origins = vec![
        "https://works.scalattice.com".to_string(),
        "http://localhost:5173".to_string(),
        "http://127.0.0.1:5173".to_string(),
        "http://localhost:4173".to_string(),
        "tauri://localhost".to_string(),
        "https://tauri.localhost".to_string(),
        "http://tauri.localhost".to_string(),
    ];
    for extra in args.cors.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        origins.push(extra.to_string());
    }

    let cors = if args.personal {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let list: Vec<_> = origins
            .into_iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let mut app = api::router();
    if state.ui_origin.is_some() {
        app = app.fallback(ui::fallback);
    }
    let app = app
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr: SocketAddr = args.bind.parse().expect("bind address");
    tracing::info!(
        %addr,
        personal = args.personal,
        data = %data.display(),
        ui = state.ui_origin.as_deref().unwrap_or("-"),
        "works-server"
    );
    if let Some(ui) = state.ui_origin.as_deref() {
        let open = if addr.ip().is_loopback() || addr.ip().is_unspecified() {
            format!("http://127.0.0.1:{}", addr.port())
        } else {
            format!("http://{addr}")
        };
        tracing::info!("open {open} in a browser (UI proxied from {ui})");
    }
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
