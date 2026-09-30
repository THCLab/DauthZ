use wasm_bindgen::prelude::*;

use dauthz_core::challenge::VerificationResult;
use dauthz_core::challenge::{CeremonyPurpose, Challenge};

use crate::store::{MemoryAccountStore, MemoryChallengeStore, MemorySessionStore, Session};
use crate::types::{JsChallenge, JsChallengeResponse, JsVerificationResult};

#[wasm_bindgen]
pub struct DauthzService {
    accounts: MemoryAccountStore,
    challenges: MemoryChallengeStore,
    sessions: MemorySessionStore,
    service_aid: String,
    service_oobi: String,
}

#[wasm_bindgen]
impl DauthzService {
    #[wasm_bindgen(constructor)]
    pub fn new(service_aid: &str, service_oobi: &str) -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            challenges: MemoryChallengeStore::new(),
            sessions: MemorySessionStore::new(),
            service_aid: service_aid.to_string(),
            service_oobi: service_oobi.to_string(),
        }
    }

    pub fn create_challenge(&mut self, purpose: &str) -> Result<JsChallenge, JsError> {
        let purpose = match purpose {
            "registration" => CeremonyPurpose::Registration,
            "identification" => CeremonyPurpose::Identification,
            _ => return Err(JsError::new("invalid purpose")),
        };

        let challenge = Challenge {
            nonce: uuid::Uuid::new_v4().to_string(),
            service_aid: self.service_aid.clone(),
            msgbox_oobi: self.service_oobi.clone(),
            service_oobi: self.service_oobi.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            purpose,
        };
        self.challenges.store(challenge.clone());
        Ok(challenge.into())
    }

    pub fn handle_response(
        &mut self,
        response: &JsChallengeResponse,
        verified: bool,
    ) -> Result<JsVerificationResult, JsError> {
        let resp = &response.inner;

        let stored = self
            .challenges
            .get(&resp.nonce)
            .cloned()
            .ok_or_else(|| JsError::new("unknown challenge nonce"))?;

        // Check expiration
        let exp: chrono::DateTime<chrono::Utc> = stored
            .expires_at
            .parse()
            .map_err(|e: chrono::ParseError| JsError::new(&format!("invalid expiration: {}", e)))?;
        if chrono::Utc::now() > exp {
            self.challenges.consume(&resp.nonce);
            return Ok(VerificationResult::Invalid("challenge expired".to_string()).into());
        }

        if !verified {
            self.challenges.consume(&resp.nonce);
            return Ok(
                VerificationResult::Invalid("signature verification failed".to_string()).into(),
            );
        }

        self.challenges.consume(&resp.nonce);

        match stored.purpose {
            CeremonyPurpose::Registration => {
                let account_id = self
                    .accounts
                    .create_account(&resp.entity_aid)
                    .map_err(|e: String| JsError::new(&e))?;
                Ok(VerificationResult::Registered {
                    aid: resp.entity_aid.clone(),
                    account_id,
                }
                .into())
            }
            CeremonyPurpose::Identification => {
                let account = self
                    .accounts
                    .get_account(&resp.entity_aid)
                    .ok_or_else(|| JsError::new("account not found"))?;
                let token = uuid::Uuid::new_v4().to_string();
                let now = chrono::Utc::now();
                let expires_at = (now + chrono::Duration::hours(1)).to_rfc3339();

                self.sessions.store(Session {
                    token: token.clone(),
                    account_id: account.id.clone(),
                    aid: resp.entity_aid.clone(),
                    created_at: now.to_rfc3339(),
                    expires_at: expires_at.clone(),
                    invalidated: false,
                });

                Ok(VerificationResult::Authenticated {
                    aid: resp.entity_aid.clone(),
                    account_id: account.id.clone(),
                    session_token: token,
                }
                .into())
            }
        }
    }

    pub fn list_accounts(&self) -> Result<JsValue, JsError> {
        let accounts = self.accounts.list_accounts();
        Ok(serde_wasm_bindgen::to_value(&accounts)?)
    }

    pub fn remove_account(&mut self, aid: &str) -> Result<(), JsError> {
        self.accounts.remove_account(aid);
        Ok(())
    }

    pub fn list_sessions(&self) -> Result<JsValue, JsError> {
        let sessions = self.sessions.list_sessions();
        Ok(serde_wasm_bindgen::to_value(&sessions)?)
    }

    pub fn invalidate_session(&mut self, token: &str) -> Result<bool, JsError> {
        Ok(self.sessions.invalidate(token))
    }

    pub fn verify_session(&self, token: &str) -> Result<JsValue, JsError> {
        let session = self.sessions.get(token);
        let result = match session {
            None => serde_wasm_bindgen::to_value(
                &serde_json::json!({"valid": false, "reason": "session not found"}),
            )?,
            Some(s) if s.invalidated => serde_wasm_bindgen::to_value(
                &serde_json::json!({"valid": false, "reason": "session invalidated"}),
            )?,
            Some(s) => {
                let exp: chrono::DateTime<chrono::Utc> = s
                    .expires_at
                    .parse()
                    .map_err(|e: chrono::ParseError| JsError::new(&format!("bad expiry: {}", e)))?;
                if chrono::Utc::now() > exp {
                    serde_wasm_bindgen::to_value(
                        &serde_json::json!({"valid": false, "reason": "session expired"}),
                    )?
                } else {
                    serde_wasm_bindgen::to_value(&serde_json::json!({
                        "valid": true,
                        "account_id": s.account_id,
                        "aid": s.aid,
                        "expires_at": s.expires_at,
                    }))?
                }
            }
        };
        Ok(result)
    }

    #[wasm_bindgen(getter)]
    pub fn aid(&self) -> String {
        self.service_aid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn oobi(&self) -> String {
        self.service_oobi.clone()
    }
}
