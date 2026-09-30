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

    /// Remove every challenge file last written more than `older_than` ago,
    /// returning how many went.
    ///
    /// A challenge is deleted only when it is answered, so one that is
    /// fetched and never answered — an abandoned login, a client retrying
    /// with a fresh challenge each time — stays forever. One broker reached a
    /// quarter of a million of them in a single directory, over its volume's
    /// size. Challenges expire minutes after they are issued, so anything
    /// much older is dead. Judged by file age rather than by parsing each
    /// record, so a sweep over a huge backlog stays cheap.
    pub fn purge_stale(&self, older_than: std::time::Duration) -> Result<usize> {
        let now = std::time::SystemTime::now();
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > older_than);
            if stale && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ChallengeStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("dauthz-challenges-{}", uuid::Uuid::new_v4()));
        (ChallengeStore::new(&dir).unwrap(), dir)
    }

    #[test]
    fn a_sweep_removes_only_challenges_older_than_the_cutoff() {
        let (store, dir) = store();
        let old = create_challenge("S", "O", "O", CeremonyPurpose::Identification);
        let fresh = create_challenge("S", "O", "O", CeremonyPurpose::Identification);
        store.store(&old).unwrap();
        store.store(&fresh).unwrap();
        let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(dir.join(format!("{}.json", old.nonce)))
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();

        let removed = store
            .purge_stale(std::time::Duration::from_secs(3600))
            .unwrap();

        assert_eq!(removed, 1);
        assert!(store.get(&old.nonce).unwrap().is_none());
        assert!(
            store.get(&fresh.nonce).unwrap().is_some(),
            "a live challenge survives"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
