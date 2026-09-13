//! axum wiring. Every route lives under `site.path_prefix` so a single
//! `location /dauthz/ { proxy_pass … }` in nginx covers the gate.

pub mod auth;
pub mod connect;
pub mod health;
pub mod login;
pub mod present;
pub mod return_url;
pub mod session;

use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use crate::ceremony::Gate;
use crate::session::SessionClaims;

pub type AppState = Arc<Gate>;

pub fn router(gate: AppState) -> Router {
    let prefix = gate.config.site.path_prefix.clone();
    // Only the wallet callback is cross-origin: the desktop/phone daemon
    // POSTs from a non-browser context, and replay is already prevented by
    // the single-use nonce (same reasoning as the Gerrit plugin).
    let callback_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS])
        .allow_headers(Any);

    let inner = Router::new()
        .route("/auth", get(auth::auth))
        .route("/login", get(login::login_page))
        .route("/ui/{file}", get(login::asset))
        .route("/connect/init", post(connect::init).get(connect::init))
        .route(
            "/connect/callback",
            post(connect::callback)
                .options(connect::callback_preflight)
                .layer(callback_cors),
        )
        .route("/connect/status", get(connect::status))
        .route("/connect/finish", get(connect::finish))
        .route("/present", get(present::page).post(present::submit))
        .route("/logout", get(session::logout).post(session::logout))
        .route("/whoami", get(session::whoami))
        .route("/healthz", get(health::healthz))
        .with_state(gate);

    Router::new().nest(&prefix, inner)
}

/// Read the session cookie, if any, and decode it.
pub fn claims_from_headers(gate: &Gate, headers: &HeaderMap) -> Option<SessionClaims> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let name = gate.config.cookie.name.as_str();
    let value = raw.split(';').map(str::trim).find_map(|kv| {
        kv.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
    })?;
    gate.codec.decode(value).ok()
}

pub fn set_cookie_header(gate: &Gate, claims: &SessionClaims) -> HeaderValue {
    let cfg = &gate.config.cookie;
    let max_age = (claims.exp - chrono::Utc::now().timestamp()).max(0);
    let mut v = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        cfg.name,
        gate.codec.encode(claims),
        max_age
    );
    if cfg.secure {
        v.push_str("; Secure");
    }
    if let Some(d) = &cfg.domain {
        v.push_str("; Domain=");
        v.push_str(d);
    }
    HeaderValue::from_str(&v).expect("cookie header is ascii")
}

pub fn clear_cookie_header(gate: &Gate) -> HeaderValue {
    let cfg = &gate.config.cookie;
    let mut v = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", cfg.name);
    if cfg.secure {
        v.push_str("; Secure");
    }
    if let Some(d) = &cfg.domain {
        v.push_str("; Domain=");
        v.push_str(d);
    }
    HeaderValue::from_str(&v).expect("cookie header is ascii")
}

pub fn redirect(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

pub fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// Minimal HTML escaping for values interpolated into pages.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
