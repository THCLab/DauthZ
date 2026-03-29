use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CeremonyPurpose {
    Registration,
    Identification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: String,
    pub service_aid: String,
    pub msgbox_oobi: String,
    pub service_oobi: String,
    pub timestamp: String,
    pub expires_at: String,
    pub purpose: CeremonyPurpose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub entity_aid: String,
    pub entity_oobi: String,
    pub nonce: String,
    pub signed_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub token: String,
    pub account_id: String,
    pub aid: String,
    pub expires_at: String,
}

impl SessionToken {
    pub fn is_valid(&self) -> bool {
        use chrono::Utc;
        match self.expires_at.parse::<chrono::DateTime<chrono::Utc>>() {
            Ok(exp) => Utc::now() < exp,
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationResult {
    Registered {
        aid: String,
        account_id: String,
    },
    Authenticated {
        aid: String,
        account_id: String,
        session_token: String,
    },
    Invalid(String),
}
