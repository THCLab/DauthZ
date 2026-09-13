//! The page presentation step: paste the wallet's `{acdc, issuer_cesr}`
//! proof to attach a credential to an AID-authenticated session.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use dauthz_core::sp_auth::PresentedCredential;
use serde::Deserialize;

use super::return_url::sanitize;
use super::{claims_from_headers, escape_html, redirect, set_cookie_header, AppState};
use crate::policy;

const PRESENT_HTML: &str = include_str!("../../assets/present.html");

#[derive(Deserialize)]
pub struct PresentForm {
    #[serde(default)]
    pub proof: String,
    #[serde(default, rename = "return")]
    pub return_to: String,
}

fn render(gate: &AppState, aid: &str, return_to: &str, error: Option<&str>) -> Response {
    let requirement = policy::requirement_text(&gate.config.policy).unwrap_or_default();
    let page = PRESENT_HTML
        .replace("{{ASSET_BASE}}", &gate.config.prefixed("/ui"))
        .replace("{{THEME_HEAD}}", &gate.config.ui.theme_head)
        .replace("{{SERVICE_NAME}}", &escape_html(&gate.config.site.name))
        .replace("{{REQUIREMENT}}", &escape_html(&requirement))
        .replace("{{AID}}", &escape_html(aid))
        .replace("{{ACTION}}", &gate.config.prefixed("/present"))
        .replace("{{LOGOUT}}", &gate.config.prefixed("/logout"))
        .replace("{{RETURN}}", &escape_html(return_to))
        .replace(
            "{{ERROR_BLOCK}}",
            &error
                .map(|e| format!(r#"<div class="status error">{}</div>"#, escape_html(e)))
                .unwrap_or_default(),
        );
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

pub async fn page(
    State(gate): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let return_to = sanitize(
        q.get("return").map(String::as_str),
        &gate.config.site.path_prefix,
    );
    let Some(claims) = claims_from_headers(&gate, &headers) else {
        return redirect(&format!(
            "{}?return={}",
            gate.config.prefixed("/login"),
            return_to
        ));
    };
    if gate.authorize(&claims) {
        return redirect(&return_to);
    }
    if !gate.config.requires_credential() {
        return StatusCode::NOT_FOUND.into_response();
    }
    render(&gate, &claims.aid, &return_to, None)
}

pub async fn submit(
    State(gate): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PresentForm>,
) -> Response {
    let return_to = sanitize(Some(&form.return_to), &gate.config.site.path_prefix);
    let Some(claims) = claims_from_headers(&gate, &headers) else {
        return redirect(&format!(
            "{}?return={}",
            gate.config.prefixed("/login"),
            return_to
        ));
    };
    let proof = match PresentedCredential::parse_proof(&form.proof) {
        Ok(p) => p,
        Err(e) => return render(&gate, &claims.aid, &return_to, Some(&e.to_string())),
    };
    match gate.present(&claims, &proof).await {
        Ok(updated) => {
            tracing::info!(aid = %updated.aid, said = ?updated.cred_said, "credential presented on page");
            let mut resp = redirect(&return_to);
            resp.headers_mut()
                .insert(header::SET_COOKIE, set_cookie_header(&gate, &updated));
            resp
        }
        Err(reason) => {
            tracing::warn!(aid = %claims.aid, "credential presentation refused: {reason}");
            render(&gate, &claims.aid, &return_to, Some(&reason))
        }
    }
}
