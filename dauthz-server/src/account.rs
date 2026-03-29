use std::collections::HashMap;
use std::path::PathBuf;

use dauthz_core::{DauthzError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub aid: String,
    pub created_at: String,
}

#[derive(Debug)]
pub struct AccountStore {
    path: PathBuf,
    accounts: HashMap<String, Account>,
}

impl AccountStore {
    pub fn new(dir: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("accounts.json");
        let accounts = if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            serde_json::from_str(&data)?
        } else {
            HashMap::new()
        };
        Ok(Self { path, accounts })
    }

    pub fn create_account(&mut self, aid: &str) -> Result<String> {
        if self.accounts.contains_key(aid) {
            return Err(DauthzError::AccountAlreadyExists(aid.to_string()));
        }

        use chrono::Utc;
        use uuid::Uuid;

        let id = Uuid::new_v4().to_string();
        let account = Account {
            id: id.clone(),
            aid: aid.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };

        self.accounts.insert(aid.to_string(), account);
        self.save()?;
        Ok(id)
    }

    pub fn get_account(&self, aid: &str) -> Result<Option<Account>> {
        Ok(self.accounts.get(aid).cloned())
    }

    pub fn list_accounts(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }

    pub fn remove_account(&mut self, aid: &str) -> Result<()> {
        self.accounts.remove(aid);
        self.save()
    }

    fn save(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.accounts)?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }
}
