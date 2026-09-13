//! Service identity bootstrap: the AID the gate presents to wallets.
//!
//! Precedence, as in `CyfronServicedBridge.ensureServiceIdentity` plus the
//! sandbox's `make init-identity`: explicit `identity.aid`+`oobi` →
//! persisted `service-identity.json` (re-checked against the daemon) →
//! `identity.alias` lookup → any existing `<slug>-xxxxxxxx` alias →
//! create one with `POST /identifiers`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bridge::{CreateIdentifier, KeriBridge};
use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub alias: String,
    pub aid: String,
    /// OOBI bag as a JSON string; goes verbatim into the deep link.
    pub oobi: String,
}

const FILE: &str = "service-identity.json";

pub fn slug(name: &str) -> String {
    let mut s = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    s.trim_matches('-').to_string()
}

pub async fn ensure_service_identity(
    cfg: &Config,
    bridge: &dyn KeriBridge,
) -> anyhow::Result<ServiceIdentity> {
    if let (Some(aid), Some(oobi)) = (&cfg.identity.aid, &cfg.identity.oobi) {
        let alias = cfg
            .identity
            .alias
            .clone()
            .unwrap_or_else(|| "pinned".into());
        bridge.set_alias(&alias);
        return Ok(ServiceIdentity {
            alias,
            aid: aid.clone(),
            oobi: oobi.clone(),
        });
    }

    let path = cfg.data_dir.join(FILE);
    if let Some(persisted) = read(&path) {
        match bridge.identifier_by_alias(&persisted.alias).await {
            Ok(Some(info)) if info.aid == persisted.aid => {
                bridge.set_alias(&persisted.alias);
                return Ok(persisted);
            }
            Ok(_) => tracing::warn!(
                "persisted service identity {} no longer exists on the daemon; re-bootstrapping",
                persisted.alias
            ),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "daemon unavailable while checking service identity: {e}"
                ))
            }
        }
    }

    let name = cfg
        .identity
        .name
        .clone()
        .unwrap_or_else(|| format!("{} gate", cfg.site.name));
    let info = if let Some(alias) = &cfg.identity.alias {
        bridge.identifier_by_alias(alias).await?.ok_or_else(|| {
            anyhow::anyhow!("identity.alias '{alias}' does not exist on the daemon")
        })?
    } else {
        let prefix = format!("{}-", slug(&name));
        let existing = bridge.list_identifiers().await?.into_iter().find(|i| {
            i.alias
                .strip_prefix(&prefix)
                .map(|rest| rest.len() == 8)
                .unwrap_or(false)
        });
        match existing {
            Some(i) => {
                tracing::info!(alias = %i.alias, "reusing service identity found on the daemon");
                bridge.identifier_by_alias(&i.alias).await?.unwrap_or(i)
            }
            None => {
                tracing::info!(name = %name, "creating service identity on the daemon (this can take a while)");
                let created = bridge
                    .create_identifier(&CreateIdentifier {
                        name: name.clone(),
                        description: format!("DauthZ gate for {}", cfg.origin()),
                        witness_urls: cfg.identity.witness_locations.clone(),
                        watcher_url: cfg.identity.watcher_location.clone(),
                    })
                    .await?;
                bridge
                    .identifier_by_alias(&created.alias)
                    .await?
                    .unwrap_or(created)
            }
        }
    };

    let identity = ServiceIdentity {
        alias: info.alias.clone(),
        aid: info.aid.clone(),
        oobi: serde_json::to_string(&info.oobi)?,
    };
    bridge.set_alias(&identity.alias);
    write(&path, &identity)?;
    Ok(identity)
}

fn read(path: &Path) -> Option<ServiceIdentity> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn write(path: &Path, identity: &ServiceIdentity) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(identity)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::mock::MockBridge;

    fn cfg(dir: &Path) -> Config {
        let mut c = Config::default();
        c.site.origin = "http://s".into();
        c.site.name = "NextGen Docs".into();
        c.data_dir = dir.to_path_buf();
        c
    }

    #[test]
    fn slug_is_stable() {
        assert_eq!(slug("NextGen Docs gate"), "nextgen-docs-gate");
        assert_eq!(slug("  a__b  "), "a-b");
    }

    #[tokio::test]
    async fn creates_persists_and_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let bridge = MockBridge::new();
        let first = ensure_service_identity(&cfg, &bridge).await.unwrap();
        assert!(first.alias.starts_with("nextgen-docs-gate-"));
        assert_eq!(bridge.alias(), first.alias);
        let second = ensure_service_identity(&cfg, &bridge).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            bridge.identifiers.lock().unwrap().len(),
            1,
            "no duplicate identity"
        );
    }

    #[tokio::test]
    async fn rebootstraps_when_daemon_lost_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let first = ensure_service_identity(&cfg, &MockBridge::new())
            .await
            .unwrap();
        let fresh = MockBridge::new();
        let second = ensure_service_identity(&cfg, &fresh).await.unwrap();
        assert_ne!(first.aid, second.aid);
    }

    #[tokio::test]
    async fn pinned_identity_skips_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg(dir.path());
        cfg.identity.aid = Some("EPIN".into());
        cfg.identity.oobi = Some("[]".into());
        let bridge = MockBridge::new();
        *bridge.fail_transport.lock().unwrap() = true;
        let id = ensure_service_identity(&cfg, &bridge).await.unwrap();
        assert_eq!(id.aid, "EPIN");
    }
}
