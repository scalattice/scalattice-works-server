use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use futures_util::TryStreamExt;

use crate::AppState;

const SKIP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "content-encoding",
    "content-length",
    "host",
];

pub async fn fallback(State(state): State<AppState>, req: Request) -> Response {
    let Some(origin) = state.ui_origin.as_deref() else {
        return (StatusCode::NOT_FOUND, "API only").into_response();
    };
    let Some(client) = state.ui_client.as_ref() else {
        return (StatusCode::NOT_FOUND, "API only").into_response();
    };
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return (StatusCode::METHOD_NOT_ALLOWED, "GET").into_response();
    }
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{origin}{path}");
    match client.get(&url).send().await {
        Ok(up) => {
            let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            for (key, value) in up.headers() {
                if SKIP.iter().any(|name| key.as_str() == *name) {
                    continue;
                }
                builder = builder.header(key, value);
            }
            let stream = up.bytes_stream().map_err(std::io::Error::other);
            builder
                .body(Body::from_stream(stream))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "ui proxy").into_response())
        }
        Err(err) => {
            tracing::warn!(%err, %url, "ui proxy");
            Html(format!(
                "<!doctype html><meta charset=utf-8><title>Works</title>\
                 <body style='font:16px/1.4 system-ui;background:#0b1220;color:#e8eefc;padding:48px'>\
                 <p>This is a Works server, but it could not load the UI from {origin}.</p>\
                 <p>{err}</p>\
                 <p>API is up at <a href='/.well-known/works.json'>/.well-known/works.json</a>.</p>"
            ))
            .into_response()
        }
    }
}
