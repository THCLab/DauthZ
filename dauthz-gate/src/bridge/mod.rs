//! The only door to KERI: a trait over the handful of `cyfron-serviced`
//! endpoints the gate needs, so the ceremony can be tested without a
//! daemon and so no KERI crate enters this repository.

pub mod cyfron_serviced;
pub mod mock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("daemon unreachable: {0}")]
    Transport(String),
    #[error("daemon returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("daemon response unparseable: {0}")]
    Parse(String),
    #[error("bridge misconfigured: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierInfo {
    pub alias: String,
    pub aid: String,
    #[serde(default)]
    pub name: String,
    /// OOBI bag as the daemon reports it (array of LocationScheme + EndRole).
    #[serde(default)]
    pub oobi: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateIdentifier {
    pub name: String,
    pub description: String,
    /// LocationScheme JSON strings.
    pub witness_urls: Vec<String>,
    pub watcher_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResolveOutcome {
    #[serde(default)]
    pub resolved: usize,
    #[serde(default)]
    pub skipped: usize,
    #[serde(default)]
    pub kel_errors: Vec<serde_json::Value>,
    #[serde(default)]
    pub kel_warnings: Vec<serde_json::Value>,
}

/// `POST /keri/verify-introduction` verdict. `authorized` is true when the
/// signer is the main AID, a confirmed delegatee of it, or a multisig
/// member — the daemon decides, the gate only requires both flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntroductionVerdict {
    pub valid: bool,
    pub authorized: bool,
    pub signer_aid: Option<String>,
}

impl IntroductionVerdict {
    pub fn accepted(&self) -> bool {
        self.valid && self.authorized
    }
}

/// Fail-closed parse of a verify-introduction body: any missing field,
/// `false`, or unparseable JSON means "not authorized". Port of
/// `CyfronServicedBridge.introductionAuthorized`.
pub fn parse_introduction_response(body: &str) -> IntroductionVerdict {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return IntroductionVerdict::default();
    };
    let flag = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    IntroductionVerdict {
        valid: flag("valid"),
        authorized: flag("authorized"),
        signer_aid: v
            .get("signer_aid")
            .and_then(|x| x.as_str())
            .map(str::to_string),
    }
}

/// Mirror of `cyfron_common::types::credential::CredentialVerification`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CredentialVerification {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub checks: Vec<CredentialCheck>,
    #[serde(default)]
    pub said: Option<String>,
    #[serde(default)]
    pub issuer_aid: Option<String>,
    #[serde(default)]
    pub schema_said: Option<String>,
    #[serde(default)]
    pub issued_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub attributes: Vec<CredentialAttribute>,
}

impl CredentialVerification {
    pub fn check(&self, id: &str) -> Option<&CredentialCheck> {
        self.checks.iter().find(|c| c.id == id)
    }

    pub fn state_of(&self, id: &str) -> CheckState {
        self.check(id)
            .map(|c| c.state)
            .unwrap_or(CheckState::Unknown)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialCheck {
    pub id: String,
    pub state: CheckState,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialAttribute {
    pub name: String,
    #[serde(default)]
    pub label: Option<String>,
    pub value: serde_json::Value,
    #[serde(default)]
    pub sensitive: bool,
}

#[async_trait]
pub trait KeriBridge: Send + Sync {
    /// Alias of the service identity used for OOBI resolution and signing.
    fn alias(&self) -> String;
    fn set_alias(&self, alias: &str);

    async fn identifier_by_alias(&self, alias: &str)
        -> Result<Option<IdentifierInfo>, BridgeError>;
    async fn list_identifiers(&self) -> Result<Vec<IdentifierInfo>, BridgeError>;
    async fn create_identifier(
        &self,
        req: &CreateIdentifier,
    ) -> Result<IdentifierInfo, BridgeError>;
    /// Pull a peer's KEL into the daemon so a later verification can find it.
    async fn resolve_oobi(&self, oobi: &serde_json::Value) -> Result<ResolveOutcome, BridgeError>;
    /// `POST /keri/verify-introduction`.
    async fn verify_introduction(
        &self,
        main_aid: &str,
        cesr: &str,
    ) -> Result<IntroductionVerdict, BridgeError>;
    /// `POST /keri/sign-cesr` with the service alias; used by smoke tooling.
    async fn sign(&self, payload: &str) -> Result<String, BridgeError>;
    /// `POST /credentials/verify`.
    async fn verify_credential(
        &self,
        acdc: &str,
        issuer_cesr: &str,
    ) -> Result<CredentialVerification, BridgeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introduction_parse_is_fail_closed() {
        assert!(parse_introduction_response(
            r#"{"valid":true,"authorized":true,"signer_aid":"ED"}"#
        )
        .accepted());
        assert!(!parse_introduction_response(r#"{"valid":true,"authorized":false}"#).accepted());
        assert!(!parse_introduction_response(r#"{"valid":false,"authorized":true}"#).accepted());
        assert!(!parse_introduction_response("{}").accepted());
        assert!(!parse_introduction_response("not json").accepted());
        assert_eq!(
            parse_introduction_response(r#"{"valid":true,"authorized":true,"signer_aid":"ED"}"#)
                .signer_aid
                .as_deref(),
            Some("ED")
        );
    }

    #[test]
    fn credential_verification_rows_are_addressable() {
        let v: CredentialVerification = serde_json::from_str(
            r#"{"ok":false,"checks":[{"id":"binding","state":"pass","detail":"x"},{"id":"revocation","state":"unknown","detail":""}],"attributes":[]}"#,
        )
        .unwrap();
        assert_eq!(v.state_of("binding"), CheckState::Pass);
        assert_eq!(v.state_of("revocation"), CheckState::Unknown);
        assert_eq!(
            v.state_of("signature"),
            CheckState::Unknown,
            "missing row reads as unknown"
        );
    }
}
