use wasm_bindgen::prelude::*;

use dauthz_core::challenge::{CeremonyPurpose, Challenge, ChallengeResponse, SessionToken};
use dauthz_core::verification::VerificationResult;

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct JsChallenge {
    inner: Challenge,
}

#[wasm_bindgen]
impl JsChallenge {
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> String {
        self.inner.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn service_aid(&self) -> String {
        self.inner.service_aid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn msgbox_oobi(&self) -> String {
        self.inner.msgbox_oobi.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn service_oobi(&self) -> String {
        self.inner.service_oobi.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> String {
        self.inner.timestamp.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn purpose(&self) -> String {
        match self.inner.purpose {
            CeremonyPurpose::Registration => "registration".to_string(),
            CeremonyPurpose::Identification => "identification".to_string(),
        }
    }

    pub fn to_json(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.inner)?)
    }

    #[wasm_bindgen(constructor)]
    pub fn from_json(value: &JsValue) -> Result<JsChallenge, JsError> {
        Ok(JsChallenge {
            inner: serde_wasm_bindgen::from_value(value.clone())?,
        })
    }
}

impl From<Challenge> for JsChallenge {
    fn from(inner: Challenge) -> Self {
        JsChallenge { inner }
    }
}

// ---------------------------------------------------------------------------
// ChallengeResponse
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct JsChallengeResponse {
    pub(crate) inner: ChallengeResponse,
}

#[wasm_bindgen]
impl JsChallengeResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        entity_aid: &str,
        entity_oobi: &str,
        nonce: &str,
        signed_challenge: &str,
    ) -> Self {
        JsChallengeResponse {
            inner: ChallengeResponse {
                entity_aid: entity_aid.to_string(),
                entity_oobi: entity_oobi.to_string(),
                nonce: nonce.to_string(),
                signed_challenge: signed_challenge.to_string(),
            },
        }
    }

    #[wasm_bindgen(getter)]
    pub fn entity_aid(&self) -> String {
        self.inner.entity_aid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn entity_oobi(&self) -> String {
        self.inner.entity_oobi.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> String {
        self.inner.nonce.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signed_challenge(&self) -> String {
        self.inner.signed_challenge.clone()
    }

    pub fn to_json(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.inner)?)
    }
}

impl From<JsChallengeResponse> for ChallengeResponse {
    fn from(js: JsChallengeResponse) -> Self {
        js.inner
    }
}

// ---------------------------------------------------------------------------
// SessionToken
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct JsSessionToken {
    inner: SessionToken,
}

#[wasm_bindgen]
impl JsSessionToken {
    #[wasm_bindgen(getter)]
    pub fn token(&self) -> String {
        self.inner.token.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn account_id(&self) -> String {
        self.inner.account_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn aid(&self) -> String {
        self.inner.aid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.clone()
    }

    pub fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    pub fn to_json(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.inner)?)
    }
}

impl From<SessionToken> for JsSessionToken {
    fn from(inner: SessionToken) -> Self {
        JsSessionToken { inner }
    }
}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct JsVerificationResult {
    kind: String,
    aid: String,
    account_id: String,
    session_token: Option<String>,
    reason: Option<String>,
}

#[wasm_bindgen]
impl JsVerificationResult {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn aid(&self) -> String {
        self.aid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session_token(&self) -> Option<String> {
        self.session_token.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }

    pub fn to_json(&self) -> Result<JsValue, JsError> {
        #[derive(serde::Serialize)]
        struct Ser<'a> {
            kind: &'a str,
            aid: &'a str,
            account_id: &'a str,
            session_token: &'a Option<String>,
            reason: &'a Option<String>,
        }
        Ok(serde_wasm_bindgen::to_value(&Ser {
            kind: &self.kind,
            aid: &self.aid,
            account_id: &self.account_id,
            session_token: &self.session_token,
            reason: &self.reason,
        })?)
    }
}

impl From<VerificationResult> for JsVerificationResult {
    fn from(vr: VerificationResult) -> Self {
        match vr {
            VerificationResult::Registered { aid, account_id } => JsVerificationResult {
                kind: "registered".to_string(),
                aid,
                account_id,
                session_token: None,
                reason: None,
            },
            VerificationResult::Authenticated {
                aid,
                account_id,
                session_token,
            } => JsVerificationResult {
                kind: "authenticated".to_string(),
                aid,
                account_id,
                session_token: Some(session_token),
                reason: None,
            },
            VerificationResult::Invalid(reason) => JsVerificationResult {
                kind: "invalid".to_string(),
                aid: String::new(),
                account_id: String::new(),
                session_token: None,
                reason: Some(reason),
            },
        }
    }
}
