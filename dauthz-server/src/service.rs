use std::path::Path;

use dauthz_core::challenge::{CeremonyPurpose, Challenge, ChallengeResponse};
use dauthz_core::challenge::VerificationResult;
use dauthz_core::{DauthzError, Result};

use crate::account::{Account, AccountStore};
use crate::challenge::{self, ChallengeStore};

#[derive(Debug)]
pub struct DauthzService {
    account_store: AccountStore,
    challenge_store: ChallengeStore,
    service_aid: String,
    service_oobi: String,
    /// When unanswered challenges were last swept (see
    /// [`ChallengeStore::purge_stale`]).
    last_sweep: std::sync::Mutex<Option<std::time::Instant>>,
}

/// How often issuing a challenge also sweeps unanswered ones.
const CHALLENGE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Age past which an unanswered challenge is removed. Challenges expire
/// after five minutes; the margin only guards against clock skew.
const CHALLENGE_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

impl DauthzService {
    pub fn new(state_dir: &Path, service_aid: &str, service_oobi: &str) -> Result<Self> {
        let dir = state_dir.join("server-state");
        let account_store = AccountStore::new(&dir.join("accounts"))?;
        let challenge_store = ChallengeStore::new(&dir.join("challenges"))?;
        Ok(Self {
            account_store,
            challenge_store,
            service_aid: service_aid.to_string(),
            service_oobi: service_oobi.to_string(),
            last_sweep: std::sync::Mutex::new(None),
        })
    }

    pub fn aid(&self) -> &str {
        &self.service_aid
    }

    pub fn oobi(&self) -> &str {
        &self.service_oobi
    }

    pub fn create_challenge(&self, purpose: CeremonyPurpose) -> Result<Challenge> {
        let challenge = challenge::create_challenge(
            &self.service_aid,
            &self.service_oobi,
            &self.service_oobi,
            purpose,
        );
        self.challenge_store.store(&challenge)?;
        self.sweep_stale_challenges();
        Ok(challenge)
    }

    /// Remove unanswered challenges, at most once per
    /// [`CHALLENGE_SWEEP_INTERVAL`]. Best-effort: a failed sweep must never
    /// cost a caller its challenge.
    fn sweep_stale_challenges(&self) {
        let Ok(mut last) = self.last_sweep.lock() else {
            return;
        };
        if last.is_some_and(|t| t.elapsed() < CHALLENGE_SWEEP_INTERVAL) {
            return;
        }
        *last = Some(std::time::Instant::now());
        let _ = self.challenge_store.purge_stale(CHALLENGE_STALE_AFTER);
    }

    pub fn handle_response(
        &mut self,
        response: ChallengeResponse,
        verified: bool,
    ) -> Result<VerificationResult> {
        let stored_challenge = self
            .challenge_store
            .get(&response.nonce)?
            .ok_or(DauthzError::UnknownChallenge)?;

        match stored_challenge
            .expires_at
            .parse::<chrono::DateTime<chrono::Utc>>()
        {
            Ok(exp) if chrono::Utc::now() > exp => {
                self.challenge_store.consume(&response.nonce)?;
                return Ok(VerificationResult::Invalid("challenge expired".to_string()));
            }
            Err(_) => {
                return Ok(VerificationResult::Invalid(
                    "invalid expiration timestamp".to_string(),
                ));
            }
            Ok(_) => {}
        }

        if !verified {
            return Ok(VerificationResult::Invalid(
                "signature verification failed".to_string(),
            ));
        }

        self.challenge_store.consume(&response.nonce)?;

        match stored_challenge.purpose {
            CeremonyPurpose::Registration => {
                let account_id = self.account_store.create_account(&response.entity_aid)?;
                Ok(VerificationResult::Registered {
                    aid: response.entity_aid,
                    account_id,
                })
            }
            CeremonyPurpose::Identification => {
                let account = self
                    .account_store
                    .get_account(&response.entity_aid)?
                    .ok_or(DauthzError::AccountNotFound)?;

                use uuid::Uuid;

                let token = Uuid::new_v4().to_string();

                Ok(VerificationResult::Authenticated {
                    aid: response.entity_aid,
                    account_id: account.id,
                    session_token: token,
                })
            }
        }
    }

    pub fn list_accounts(&self) -> Vec<&Account> {
        self.account_store.list_accounts()
    }
}
