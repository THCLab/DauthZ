//! In-memory challenge and pending-session stores, a port of the Gerrit
//! plugin's `ChallengeStore` / `PendingSessionStore`. Single-process by
//! design for v1: a restart drops in-flight ceremonies only, because the
//! session itself lives in a stateless cookie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dauthz_core::Challenge;

use crate::session::SessionClaims;

#[derive(Default)]
pub struct ChallengeStore {
    inner: Mutex<HashMap<String, Challenge>>,
}

impl ChallengeStore {
    pub fn store(&self, challenge: Challenge) {
        self.inner
            .lock()
            .unwrap()
            .insert(challenge.nonce.clone(), challenge);
    }

    pub fn get(&self, nonce: &str) -> Option<Challenge> {
        self.inner.lock().unwrap().get(nonce).cloned()
    }

    /// Single use: a nonce is removed on every exit path of a callback.
    pub fn consume(&self, nonce: &str) -> Option<Challenge> {
        self.inner.lock().unwrap().remove(nonce)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn reap(&self, now: DateTime<Utc>) -> usize {
        let mut map = self.inner.lock().unwrap();
        let before = map.len();
        map.retain(|_, c| parse_ts(&c.expires_at).map(|e| e > now).unwrap_or(false));
        before - map.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    Pending,
    /// Signed in; may still need a credential (see `needs_credential`).
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct PendingSession {
    pub nonce: String,
    pub state: PendingState,
    pub expires_at: DateTime<Utc>,
    pub return_to: String,
    pub handoff_token: Option<String>,
    pub claims: Option<SessionClaims>,
    /// True when policy requires a credential the callback did not carry;
    /// `finish` then lands on the presentation page instead of `return_to`.
    pub needs_credential: bool,
    pub failure_reason: Option<String>,
}

#[derive(Default)]
pub struct PendingSessionStore {
    by_nonce: Mutex<HashMap<String, PendingSession>>,
    by_token: Mutex<HashMap<String, String>>,
}

impl PendingSessionStore {
    pub fn create(&self, nonce: &str, return_to: &str, ttl: Duration) {
        let session = PendingSession {
            nonce: nonce.to_string(),
            state: PendingState::Pending,
            expires_at: Utc::now()
                + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::minutes(5)),
            return_to: return_to.to_string(),
            handoff_token: None,
            claims: None,
            needs_credential: false,
            failure_reason: None,
        };
        self.by_nonce
            .lock()
            .unwrap()
            .insert(nonce.to_string(), session);
    }

    pub fn get(&self, nonce: &str) -> Option<PendingSession> {
        self.by_nonce.lock().unwrap().get(nonce).cloned()
    }

    /// Mark approved and mint a single-use handoff token.
    pub fn approve(
        &self,
        nonce: &str,
        claims: SessionClaims,
        needs_credential: bool,
    ) -> Option<String> {
        let mut map = self.by_nonce.lock().unwrap();
        let session = map.get_mut(nonce)?;
        if session.state != PendingState::Pending {
            return None;
        }
        let token = random_token();
        session.state = PendingState::Approved;
        session.claims = Some(claims);
        session.needs_credential = needs_credential;
        session.handoff_token = Some(token.clone());
        self.by_token
            .lock()
            .unwrap()
            .insert(token.clone(), nonce.to_string());
        Some(token)
    }

    pub fn deny(&self, nonce: &str, reason: &str) {
        let mut map = self.by_nonce.lock().unwrap();
        if let Some(session) = map.get_mut(nonce) {
            if session.state == PendingState::Pending {
                session.state = PendingState::Denied;
                session.failure_reason = Some(reason.to_string());
            }
        }
    }

    /// Exchange a handoff token exactly once for the approved session.
    pub fn consume_handoff(&self, token: &str) -> Option<PendingSession> {
        let nonce = self.by_token.lock().unwrap().remove(token)?;
        let session = self.by_nonce.lock().unwrap().remove(&nonce)?;
        if session.state != PendingState::Approved
            || session.handoff_token.as_deref() != Some(token)
        {
            return None;
        }
        Some(session)
    }

    pub fn reap(&self, now: DateTime<Utc>) -> usize {
        let mut map = self.by_nonce.lock().unwrap();
        let mut tokens = self.by_token.lock().unwrap();
        let before = map.len();
        map.retain(|_, s| s.expires_at > now);
        tokens.retain(|_, nonce| map.contains_key(nonce));
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.by_nonce.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn random_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().ok()
}

/// Reap both stores every `every`; port of the 60 s daemon threads.
pub fn spawn_reaper(
    challenges: Arc<ChallengeStore>,
    pending: Arc<PendingSessionStore>,
    every: Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let now = Utc::now();
            let c = challenges.reap(now);
            let p = pending.reap(now);
            if c + p > 0 {
                tracing::debug!(
                    challenges = c,
                    sessions = p,
                    "reaped expired ceremony state"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use dauthz_core::CeremonyPurpose;

    fn challenge(nonce: &str, secs: i64) -> Challenge {
        Challenge {
            nonce: nonce.into(),
            service_aid: "E".into(),
            msgbox_oobi: String::new(),
            service_oobi: "[]".into(),
            timestamp: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339(),
            purpose: CeremonyPurpose::Identification,
        }
    }

    #[test]
    fn nonce_is_single_use_and_expired_ones_are_reaped() {
        let store = ChallengeStore::default();
        store.store(challenge("a", 60));
        store.store(challenge("b", -1));
        assert_eq!(store.reap(Utc::now()), 1);
        assert!(store.consume("a").is_some());
        assert!(store.consume("a").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn handoff_token_is_single_use_and_only_after_approval() {
        let store = PendingSessionStore::default();
        store.create("n", "/x", Duration::from_secs(60));
        assert!(store.consume_handoff("nope").is_none());
        let token = store
            .approve("n", SessionClaims::new("E", None, 10), false)
            .unwrap();
        assert!(
            store
                .approve("n", SessionClaims::new("E", None, 10), false)
                .is_none(),
            "second approve refused"
        );
        let s = store.consume_handoff(&token).unwrap();
        assert_eq!(s.return_to, "/x");
        assert!(store.consume_handoff(&token).is_none(), "replay refused");
        assert!(store.is_empty());
    }

    #[test]
    fn deny_only_moves_pending_sessions() {
        let store = PendingSessionStore::default();
        store.create("n", "/", Duration::from_secs(60));
        store.deny("n", "bad");
        assert_eq!(store.get("n").unwrap().state, PendingState::Denied);
        assert!(store
            .approve("n", SessionClaims::new("E", None, 10), false)
            .is_none());
        store.deny("n", "again");
        assert_eq!(
            store.get("n").unwrap().failure_reason.as_deref(),
            Some("bad")
        );
    }

    #[test]
    fn reaper_drops_tokens_of_expired_sessions() {
        let store = PendingSessionStore::default();
        store.create("n", "/", Duration::from_secs(0));
        let token = store
            .approve("n", SessionClaims::new("E", None, 10), false)
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(store.reap(Utc::now()), 1);
        assert!(store.consume_handoff(&token).is_none());
    }
}
