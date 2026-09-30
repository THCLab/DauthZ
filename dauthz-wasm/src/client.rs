use wasm_bindgen::prelude::*;

use dauthz_core::challenge::{CeremonyPurpose, ChallengeResponse};

use crate::transport;
use crate::types::{JsChallenge, JsChallengeResponse, JsSessionToken};

#[wasm_bindgen]
pub struct DauthzClient;

#[wasm_bindgen]
impl DauthzClient {
    /// Request a challenge from the service.
    /// `purpose` must be "registration" or "identification".
    pub async fn request_challenge(
        service_url: &str,
        purpose: &str,
    ) -> Result<JsChallenge, JsError> {
        let purpose = parse_purpose(purpose)?;
        let challenge = transport::fetch_get_challenge(service_url, purpose).await?;
        Ok(challenge.into())
    }

    /// Submit a signed challenge response to the service.
    pub async fn submit_response(
        service_url: &str,
        response: &JsChallengeResponse,
    ) -> Result<JsSessionToken, JsError> {
        let token = transport::fetch_submit_response(service_url, &response.inner.clone()).await?;
        Ok(token.into())
    }

    /// Full registration ceremony.
    /// `sign_fn` is an async JS function that takes a JSON string and returns a Promise<string> (the signed data).
    pub async fn register(
        service_url: &str,
        entity_aid: &str,
        entity_oobi: &str,
        sign_fn: &js_sys::Function,
    ) -> Result<String, JsError> {
        let challenge =
            transport::fetch_get_challenge(service_url, CeremonyPurpose::Registration).await?;

        let signed = call_sign_fn(sign_fn, &challenge).await?;

        let response = ChallengeResponse {
            entity_aid: entity_aid.to_string(),
            entity_oobi: entity_oobi.to_string(),
            nonce: challenge.nonce,
            signed_challenge: signed,
        };
        transport::fetch_submit_response(service_url, &response).await?;
        Ok(entity_aid.to_string())
    }

    /// Full login ceremony.
    /// `sign_fn` is an async JS function that takes a JSON string and returns a Promise<string> (the signed data).
    pub async fn login(
        service_url: &str,
        entity_aid: &str,
        entity_oobi: &str,
        sign_fn: &js_sys::Function,
    ) -> Result<JsSessionToken, JsError> {
        let challenge =
            transport::fetch_get_challenge(service_url, CeremonyPurpose::Identification).await?;

        let signed = call_sign_fn(sign_fn, &challenge).await?;

        let response = ChallengeResponse {
            entity_aid: entity_aid.to_string(),
            entity_oobi: entity_oobi.to_string(),
            nonce: challenge.nonce,
            signed_challenge: signed,
        };
        let token = transport::fetch_submit_response(service_url, &response).await?;
        Ok(token.into())
    }
}

fn parse_purpose(purpose: &str) -> Result<CeremonyPurpose, JsError> {
    match purpose {
        "registration" => Ok(CeremonyPurpose::Registration),
        "identification" => Ok(CeremonyPurpose::Identification),
        _ => Err(JsError::new(&format!(
            "invalid purpose '{}', expected 'registration' or 'identification'",
            purpose
        ))),
    }
}

async fn call_sign_fn(
    sign_fn: &js_sys::Function,
    challenge: &dauthz_core::challenge::Challenge,
) -> Result<String, JsError> {
    let challenge_json = serde_json::to_string(challenge)?;
    let challenge_js = JsValue::from(challenge_json);
    let promise = sign_fn
        .call1(&JsValue::NULL, &challenge_js)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let result = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&promise))
        .await
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;
    result
        .as_string()
        .ok_or_else(|| JsError::new("sign_fn must return a string"))
}
