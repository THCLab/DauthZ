//! A scripted [`KeriBridge`] for tests and the `--mock-bridge` dev mode.
//!
//! Signed streams are `<json>-MOCK:<signer_aid>`; the mock reads the
//! signer from the attachment and reports `authorized` when the signer is
//! the main AID or a delegate registered with [`MockBridge::delegate`].
//! Credentials are "signed" by `-MOCK-ISSUER:<issuer_aid>`; the mock checks
//! it against the ACDC's `i` and reports the configured revocation state.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;

use super::*;

#[derive(Default)]
pub struct MockBridge {
    alias: Mutex<String>,
    pub identifiers: Mutex<Vec<IdentifierInfo>>,
    /// (device_aid, main_aid) pairs the mock treats as confirmed delegations.
    delegates: Mutex<HashSet<(String, String)>>,
    /// Revocation row state per credential SAID (default: unknown).
    revocation: Mutex<HashMap<String, CheckState>>,
    pub resolved: Mutex<Vec<serde_json::Value>>,
    pub verify_calls: Mutex<Vec<(String, String)>>,
    pub fail_transport: Mutex<bool>,
}

impl MockBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_identity(self, alias: &str, aid: &str) -> Self {
        self.identifiers.lock().unwrap().push(IdentifierInfo {
            alias: alias.into(),
            aid: aid.into(),
            name: alias.into(),
            oobi: serde_json::json!([
                {"eid":"BWIT","scheme":"http","url":"http://witness.test/"},
                {"cid": aid, "role":"witness","eid":"BWIT"}
            ]),
        });
        *self.alias.lock().unwrap() = alias.into();
        self
    }

    pub fn delegate(&self, device_aid: &str, main_aid: &str) {
        self.delegates
            .lock()
            .unwrap()
            .insert((device_aid.into(), main_aid.into()));
    }

    pub fn set_revocation(&self, said: &str, state: CheckState) {
        self.revocation.lock().unwrap().insert(said.into(), state);
    }

    /// Build a stream the mock will accept as signed by `signer`.
    pub fn sign_as(signer: &str, json: &str) -> String {
        format!("{json}-MOCK:{signer}")
    }

    pub fn issuer_sig(issuer: &str) -> String {
        format!("-MOCK-ISSUER:{issuer}")
    }

    fn transport_guard(&self) -> Result<(), BridgeError> {
        if *self.fail_transport.lock().unwrap() {
            Err(BridgeError::Transport("mock daemon down".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl KeriBridge for MockBridge {
    fn alias(&self) -> String {
        self.alias.lock().unwrap().clone()
    }

    fn set_alias(&self, alias: &str) {
        *self.alias.lock().unwrap() = alias.into();
    }

    async fn identifier_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentifierInfo>, BridgeError> {
        self.transport_guard()?;
        Ok(self
            .identifiers
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.alias == alias)
            .cloned())
    }

    async fn list_identifiers(&self) -> Result<Vec<IdentifierInfo>, BridgeError> {
        self.transport_guard()?;
        Ok(self.identifiers.lock().unwrap().clone())
    }

    async fn create_identifier(
        &self,
        req: &CreateIdentifier,
    ) -> Result<IdentifierInfo, BridgeError> {
        self.transport_guard()?;
        let slug = req.name.to_lowercase().replace(' ', "-");
        let alias = format!("{slug}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let aid = format!("E{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        let info = IdentifierInfo {
            alias: alias.clone(),
            aid: aid.clone(),
            name: req.name.clone(),
            oobi: serde_json::json!([{"cid": aid, "role": "witness", "eid": "BWIT"}]),
        };
        self.identifiers.lock().unwrap().push(info.clone());
        Ok(info)
    }

    async fn resolve_oobi(&self, oobi: &serde_json::Value) -> Result<ResolveOutcome, BridgeError> {
        self.transport_guard()?;
        self.resolved.lock().unwrap().push(oobi.clone());
        Ok(ResolveOutcome {
            resolved: 1,
            ..Default::default()
        })
    }

    async fn verify_introduction(
        &self,
        main_aid: &str,
        cesr: &str,
    ) -> Result<IntroductionVerdict, BridgeError> {
        self.transport_guard()?;
        self.verify_calls
            .lock()
            .unwrap()
            .push((main_aid.into(), cesr.into()));
        let Some(signer) = cesr
            .rsplit_once("-MOCK:")
            .map(|(_, s)| s.to_string())
            .or_else(|| {
                cesr.rsplit_once("-MOCK-ISSUER:")
                    .map(|(_, s)| s.to_string())
            })
        else {
            return Ok(IntroductionVerdict::default());
        };
        let is_self = signer == main_aid;
        let delegatee = self
            .delegates
            .lock()
            .unwrap()
            .contains(&(signer.clone(), main_aid.to_string()));
        Ok(IntroductionVerdict {
            valid: true,
            authorized: is_self || delegatee,
            signer_aid: Some(signer),
        })
    }

    async fn sign(&self, payload: &str) -> Result<String, BridgeError> {
        self.transport_guard()?;
        let aid = self
            .identifiers
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.alias == self.alias())
            .map(|i| i.aid.clone())
            .unwrap_or_else(|| "EUNKNOWN".into());
        Ok(Self::sign_as(&aid, payload))
    }

    async fn verify_credential(
        &self,
        acdc: &str,
        issuer_cesr: &str,
    ) -> Result<CredentialVerification, BridgeError> {
        self.transport_guard()?;
        let row = |id: &str, state: CheckState| CredentialCheck {
            id: id.into(),
            state,
            detail: String::new(),
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(acdc) else {
            return Ok(CredentialVerification {
                ok: false,
                checks: vec![row("binding", CheckState::Fail)],
                ..Default::default()
            });
        };
        let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let said = field("d");
        let issuer = field("i");
        let binding = if said
            .as_deref()
            .map(|s| s.starts_with("EBAD"))
            .unwrap_or(true)
        {
            CheckState::Fail
        } else {
            CheckState::Pass
        };
        let signature = match issuer_cesr.strip_prefix("-MOCK-ISSUER:") {
            Some(s) if Some(s) == issuer.as_deref() => CheckState::Pass,
            Some(_) => CheckState::Fail,
            None => CheckState::Unknown,
        };
        let expires_at = v
            .get("a")
            .and_then(|a| a.get("exp"))
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let validity = match &expires_at {
            None => CheckState::Pass,
            Some(e) => match e.parse::<chrono::DateTime<chrono::Utc>>() {
                Ok(t) if t > chrono::Utc::now() => CheckState::Pass,
                _ => CheckState::Fail,
            },
        };
        let revocation = said
            .as_deref()
            .and_then(|s| self.revocation.lock().unwrap().get(s).copied())
            .unwrap_or(CheckState::Unknown);
        let checks = vec![
            row("binding", binding),
            row("signature", signature),
            row("revocation", revocation),
            row("validity", validity),
        ];
        Ok(CredentialVerification {
            ok: checks.iter().all(|c| c.state == CheckState::Pass),
            checks,
            said,
            issuer_aid: issuer,
            schema_said: field("s"),
            issued_at: v
                .get("a")
                .and_then(|a| a.get("dt"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            expires_at,
            attributes: Vec::new(),
        })
    }
}
