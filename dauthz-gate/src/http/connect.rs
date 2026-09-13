//! The wallet ceremony endpoints, wire compatible with the Gerrit plugin's
//! `/connect/*` servlets so the shared login JS drives them unchanged.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dauthz_core::sp_auth::CallbackBody;

use super::return_url::sanitize;
use super::{json_error, redirect, set_cookie_header, AppState};
use crate::ceremony::CallbackOutcome;

pub async fn init(
    State(gate): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let return_to = sanitize(
        q.get("return").map(String::as_str),
        &gate.config.site.path_prefix,
    );
    match gate.init(&return_to).await {
        Ok(resp) => ([(header::CACHE_CONTROL, "no-store")], Json(resp)).into_response(),
        Err(e) => json_error(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

pub async fn callback_preflight() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn callback(State(gate): State<AppState>, body: axum::body::Bytes) -> Response {
    let parsed: CallbackBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("invalid callback body: {e}"),
            )
        }
    };
    match gate.callback(parsed).await {
        CallbackOutcome::Declined => Json(serde_json::json!({ "kind": "denied" })).into_response(),
        CallbackOutcome::Authenticated {
            aid,
            needs_credential,
        } => Json(serde_json::json!({
            "kind": "authenticated",
            "aid": aid,
            "needs_credential": needs_credential,
        }))
        .into_response(),
        CallbackOutcome::Rejected { status, reason } => json_error(
            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            &reason,
        ),
    }
}

pub async fn status(
    State(gate): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(nonce) = q.get("nonce") else {
        return json_error(StatusCode::BAD_REQUEST, "missing nonce");
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(gate.status(nonce)),
    )
        .into_response()
}

pub async fn finish(
    State(gate): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(token) = q.get("token") else {
        return json_error(StatusCode::BAD_REQUEST, "missing token");
    };
    let Some(outcome) = gate.finish(token) else {
        return json_error(
            StatusCode::FORBIDDEN,
            "unknown or already used handoff token",
        );
    };
    let target = if outcome.needs_credential {
        format!(
            "{}?return={}",
            gate.config.prefixed("/present"),
            dauthz_core::sp_auth::form_urlencode(&outcome.return_to)
        )
    } else {
        outcome.return_to.clone()
    };
    let mut resp = redirect(&target);
    resp.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie_header(&gate, &outcome.claims),
    );
    resp
}
