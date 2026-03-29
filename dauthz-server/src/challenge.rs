use dauthz_core::challenge::{CeremonyPurpose, Challenge};
use dauthz_core::Result;

#[derive(Debug)]
pub struct ChallengeStore {
    dir: std::path::PathBuf,
}

impl ChallengeStore {
    pub fn new(dir: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn store(&self, challenge: &Challenge) -> Result<()> {
        let path = self.dir.join(format!("{}.json", challenge.nonce));
        let data = serde_json::to_string_pretty(challenge)?;
        std::fs::write(&path, data)?;
        Ok(())
    }

    pub fn get(&self, nonce: &str) -> Result<Option<Challenge>> {
        let path = self.dir.join(format!("{}.json", nonce));
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let challenge: Challenge = serde_json::from_str(&data)?;
        Ok(Some(challenge))
    }

    pub fn consume(&self, nonce: &str) -> Result<()> {
        let path = self.dir.join(format!("{}.json", nonce));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

pub fn create_challenge(
    service_aid: &str,
    service_oobi: &str,
    msgbox_oobi: &str,
    purpose: CeremonyPurpose,
) -> Challenge {
    use chrono::Utc;
    use uuid::Uuid;

    Challenge {
        nonce: Uuid::new_v4().to_string(),
        service_aid: service_aid.to_string(),
        msgbox_oobi: msgbox_oobi.to_string(),
        service_oobi: service_oobi.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        purpose,
    }
}
