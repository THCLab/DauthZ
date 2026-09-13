//! `GET /auth`: the `auth_request` target. 204 with `X-DauthZ-AID` when
//! the cookie is valid and still allowed, 401 otherwise. nginx turns the
//! 401 into a redirect to the login page.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::{claims_from_headers, AppState};

pub async fn auth(State(gate): State<AppState>, headers: HeaderMap) -> Response {
    match claims_from_headers(&gate, &headers) {
        Some(claims) if gate.authorize(&claims) => (
            StatusCode::NO_CONTENT,
            [
                (header::CACHE_CONTROL, "no-store".to_string()),
                (
                    header::HeaderName::from_static("x-dauthz-aid"),
                    claims.aid.clone(),
                ),
                (
                    header::HeaderName::from_static("x-dauthz-session"),
                    claims.sid.clone(),
                ),
            ],
        )
            .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
    }
}
