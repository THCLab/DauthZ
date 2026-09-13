use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::AppState;

pub async fn healthz(State(gate): State<AppState>) -> Response {
    let identity = gate.identity().await;
    let daemon_reachable = gate.bridge.list_identifiers().await.is_ok();
    let ready = identity.is_some();
    let body = serde_json::json!({
        "ok": true,
        "ready": ready,
        "daemon_reachable": daemon_reachable,
        "service_alias": identity.as_ref().map(|i| i.alias.clone()),
        "service_aid": identity.as_ref().map(|i| i.aid.clone()),
        "policy_mode": gate.policy_mode(),
        "callback_url": gate.config.callback_url(),
        "pending_sessions": gate.pending.len(),
        "uptime_secs": (chrono::Utc::now() - gate.started_at).num_seconds(),
    });
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(body),
    )
        .into_response()
}
