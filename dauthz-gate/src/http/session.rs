use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{claims_from_headers, clear_cookie_header, redirect, AppState};

pub async fn logout(State(gate): State<AppState>) -> Response {
    let mut resp = redirect(&gate.config.prefixed("/login"));
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_cookie_header(&gate));
    resp
}

pub async fn whoami(State(gate): State<AppState>, headers: HeaderMap) -> Response {
    match claims_from_headers(&gate, &headers) {
        Some(claims) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "aid": claims.aid,
                "signer_aid": claims.signer_aid,
                "cred_said": claims.cred_said,
                "exp": claims.exp,
                "authorized": gate.authorize(&claims),
            })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
    }
}
