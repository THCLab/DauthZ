//! The sign-in page (shared `dauthz-login-ui` bundle) and its assets,
//! embedded at compile time from `../dauthz-login-ui/assets`.

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use super::return_url::{raw_return, sanitize};
use super::{claims_from_headers, redirect, AppState};
use crate::policy;

const LOGIN_HTML: &str = include_str!("../../../dauthz-login-ui/assets/dauthz-login.html");
const LOGIN_CSS: &str = include_str!("../../../dauthz-login-ui/assets/dauthz-login.css");
const LOGIN_JS: &str = include_str!("../../../dauthz-login-ui/assets/dauthz-login.js");
const QRCODE_JS: &str = include_str!("../../../dauthz-login-ui/assets/qrcode.min.js");
pub const UI_VERSION: &str = include_str!("../../../dauthz-login-ui/VERSION");

pub async fn login_page(
    State(gate): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let prefix = &gate.config.site.path_prefix;
    let return_to = sanitize(raw_return(query.as_deref()).as_deref(), prefix);

    if let Some(claims) = claims_from_headers(&gate, &headers) {
        if gate.authorize(&claims) {
            return redirect(&return_to);
        }
        if gate.config.requires_credential() && claims.cred_said.is_none() {
            return redirect(&format!(
                "{}?return={}",
                gate.config.prefixed("/present"),
                dauthz_core::sp_auth::form_urlencode(&return_to)
            ));
        }
    }

    let identity = gate.identity().await;
    let config = serde_json::json!({
        "pluginBase": prefix,
        "serviceName": gate.config.site.name,
        "registrationMode": "open",
        "requestedAttrs": "nothing beyond your AID",
        "serviceOobi": identity.as_ref().map(|i| i.oobi.clone()).unwrap_or_default(),
        // The page prints its own UI version; this names the backend.
        "buildVersion": format!("dauthz-gate {}", env!("CARGO_PKG_VERSION")),
        "returnTo": return_to,
        "hideInvite": true,
        "accessRequirement": policy::requirement_text(&gate.config.policy),
    });
    let page = LOGIN_HTML
        .replace("{{ASSET_BASE}}", &gate.config.prefixed("/ui"))
        .replace("{{THEME_HEAD}}", &gate.config.ui.theme_head)
        .replace("/*__DAUTHZ_CONFIG__*/{}", &config.to_string());
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

pub async fn asset(Path(file): Path<String>) -> Response {
    let (body, mime): (&'static str, &'static str) = match file.as_str() {
        "dauthz-login.css" => (LOGIN_CSS, "text/css; charset=utf-8"),
        "dauthz-login.js" => (LOGIN_JS, "application/javascript; charset=utf-8"),
        "qrcode.min.js" => (QRCODE_JS, "application/javascript; charset=utf-8"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_ui_version_matches_version_file() {
        let expected = format!("const UI_VERSION = '{}';", UI_VERSION.trim());
        assert!(
            LOGIN_JS.contains(&expected),
            "dauthz-login.js UI_VERSION must match dauthz-login-ui/VERSION ({})",
            UI_VERSION.trim()
        );
    }
}
