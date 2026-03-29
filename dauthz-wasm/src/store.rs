use std::collections::HashMap;

use dauthz_core::challenge::Challenge;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub aid: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub account_id: String,
    pub aid: String,
    pub created_at: String,
    pub expires_at: String,
    pub invalidated: bool,
}

#[derive(Debug, Default)]
pub struct MemoryAccountStore {
    accounts: HashMap<String, Account>,
}

impl MemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_account(&mut self, aid: &str) -> Result<String, String> {
        if self.accounts.contains_key(aid) {
            return Err(format!("account already exists for AID: {}", aid));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let account = Account {
            id: id.clone(),
            aid: aid.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.accounts.insert(aid.to_string(), account);
        Ok(id)
    }

    pub fn get_account(&self, aid: &str) -> Option<&Account> {
        self.accounts.get(aid)
    }

    pub fn list_accounts(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }

    pub fn remove_account(&mut self, aid: &str) {
        self.accounts.remove(aid);
    }
}

#[derive(Debug, Default)]
pub struct MemoryChallengeStore {
    challenges: HashMap<String, Challenge>,
}

impl MemoryChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, challenge: Challenge) {
        self.challenges.insert(challenge.nonce.clone(), challenge);
    }

    pub fn get(&self, nonce: &str) -> Option<&Challenge> {
        self.challenges.get(nonce)
    }

    pub fn consume(&mut self, nonce: &str) {
        self.challenges.remove(nonce);
    }
}

#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: HashMap<String, Session>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, session: Session) {
        self.sessions.insert(session.token.clone(), session);
    }

    pub fn get(&self, token: &str) -> Option<&Session> {
        self.sessions.get(token)
    }

    pub fn list_sessions(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }

    pub fn invalidate(&mut self, token: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(token) {
            s.invalidated = true;
            true
        } else {
            false
        }
    }
}
