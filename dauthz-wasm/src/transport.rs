use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use dauthz_core::challenge::{CeremonyPurpose, Challenge, ChallengeResponse, SessionToken};

/// Convert a `JsValue` error into `JsError`.
fn js_err(val: JsValue) -> JsError {
    JsError::new(&format!("{:?}", val))
}

pub async fn fetch_json<T: serde::de::DeserializeOwned>(
    url: &str,
    method: &str,
    body: Option<&str>,
) -> Result<T, JsError> {
    let opts = RequestInit::new();
    opts.set_method(method);
    opts.set_mode(RequestMode::Cors);

    if let Some(b) = body {
        opts.set_body(&JsValue::from(b));
    }

    let request = Request::new_with_str_and_init(url, &opts).map_err(js_err)?;
    let headers = request.headers();
    headers
        .set("Content-Type", "application/json")
        .map_err(js_err)?;
    headers.set("Accept", "application/json").map_err(js_err)?;

    let window = web_sys::window().ok_or_else(|| JsError::new("no window available"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(js_err)?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("fetch did not return Response"))?;

    if !resp.ok() {
        let status = resp.status();
        let text = JsFuture::from(resp.text().map_err(js_err)?)
            .await
            .map_err(js_err)?
            .as_string()
            .unwrap_or_default();
        return Err(JsError::new(&format!("HTTP {}: {}", status, text)));
    }

    let text = JsFuture::from(resp.text().map_err(js_err)?)
        .await
        .map_err(js_err)?
        .as_string()
        .ok_or_else(|| JsError::new("response body is not text"))?;
    let data: T = serde_json::from_str(&text)?;
    Ok(data)
}

pub async fn fetch_get_challenge(
    service_url: &str,
    purpose: CeremonyPurpose,
) -> Result<Challenge, JsError> {
    let endpoint = match purpose {
        CeremonyPurpose::Registration => "register",
        CeremonyPurpose::Identification => "login",
    };
    let url = format!("{}/dauthz/{}", service_url.trim_end_matches('/'), endpoint);
    fetch_json(&url, "GET", None).await
}

pub async fn fetch_submit_response(
    service_url: &str,
    response: &ChallengeResponse,
) -> Result<SessionToken, JsError> {
    let url = format!("{}/dauthz/respond", service_url.trim_end_matches('/'));
    let body = serde_json::to_string(response)?;
    fetch_json(&url, "POST", Some(&body)).await
}
