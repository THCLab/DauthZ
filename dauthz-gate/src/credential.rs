//! Research-passport verification: the wallet's `{acdc, issuer_cesr}` proof
//! against the configured (schema SAID, issuer AID) pair and the holder's
//! proven main AID.
//!
//! The daemon answers four independent questions (`/credentials/verify`);
//! the gate reads each row rather than the aggregate `ok`, because the
//! aggregate demands a live registry answer and this policy is
//! signature-only by choice. The gate then adds what the daemon does not
//! assert: which schema, which issuer, which holder, and — via
//! `verify-introduction` on the issuer — that the signer is entitled to
//! act for the issuer (delegated devices, multisig members).

use dauthz_core::sp_auth::PresentedCredential;

use crate::bridge::{CheckState, KeriBridge};
use crate::config::{PolicyConfig, RevocationCheck};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPassport {
    pub said: String,
    pub expires_at: Option<String>,
}

pub async fn verify_presented(
    bridge: &dyn KeriBridge,
    policy: &PolicyConfig,
    main_aid: &str,
    presented: &PresentedCredential,
) -> Result<VerifiedPassport, String> {
    let schema = policy
        .schema_said
        .as_deref()
        .ok_or("policy has no schema_said")?;
    let issuer = policy
        .issuer_aid
        .as_deref()
        .ok_or("policy has no issuer_aid")?;

    if presented.issuer_cesr.trim().is_empty() {
        return Err("the proof carries no issuer signature".into());
    }
    // Facts read from the container itself, never from the daemon's echo.
    let said = presented.said().ok_or("credential has no SAID")?;
    let holder = presented
        .subject_aid()
        .ok_or("credential names no holder (a.i)")?;
    if holder != main_aid {
        return Err(format!(
            "credential was issued to {holder}, not to the signed-in AID"
        ));
    }
    if presented.schema_said().as_deref() != Some(schema) {
        return Err("credential schema is not the expected OCA bundle".into());
    }
    if presented.issuer_aid().as_deref() != Some(issuer) {
        return Err("credential was not issued by the expected authority".into());
    }

    let report = bridge
        .verify_credential(&presented.acdc, &presented.issuer_cesr)
        .await
        .map_err(|e| format!("credential verification unavailable: {e}"))?;

    if report.said.as_deref() != Some(said.as_str()) {
        return Err("daemon verified a different credential than presented".into());
    }
    for id in ["binding", "signature", "validity"] {
        if report.state_of(id) != CheckState::Pass {
            let detail = report
                .check(id)
                .map(|c| c.detail.clone())
                .unwrap_or_default();
            return Err(format!("credential {id} check failed: {detail}"));
        }
    }
    match (policy.revocation_check, report.state_of("revocation")) {
        (RevocationCheck::Off, _) => {}
        (RevocationCheck::IfKnown, CheckState::Fail) => {
            return Err("credential has been revoked".into())
        }
        (RevocationCheck::IfKnown, _) => {}
        (RevocationCheck::Required, CheckState::Pass) => {}
        (RevocationCheck::Required, _) => {
            return Err("credential registry status could not be confirmed".into())
        }
    }

    // The daemon's signature row proves *a* signature by the `i` AID's
    // KEL; verify-introduction additionally accepts a delegated device or
    // multisig member of the issuer, and refuses an unrelated signer.
    let verdict = bridge
        .verify_introduction(issuer, &presented.signed_stream())
        .await
        .map_err(|e| format!("issuer signature verification unavailable: {e}"))?;
    if !verdict.accepted() {
        return Err("issuer signature is not by the authority or one of its delegates".into());
    }

    Ok(VerifiedPassport {
        said,
        expires_at: report.expires_at,
    })
}

/// Unix timestamp of an RFC3339 expiry, for capping the session.
pub fn expiry_ts(expires_at: Option<&str>) -> Option<i64> {
    expires_at?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .ok()
        .map(|t| t.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::mock::MockBridge;

    const ISSUER: &str = "EISSUER";
    const SCHEMA: &str = "ESCHEMA";
    const HOLDER: &str = "EHOLDER";

    fn acdc(said: &str, issuer: &str, schema: &str, holder: &str, exp: Option<&str>) -> String {
        let exp = exp.map(|e| format!(r#","exp":"{e}""#)).unwrap_or_default();
        format!(
            r#"{{"v":"ACDC10JSON0000fb_","d":"{said}","i":"{issuer}","ri":"EREG","s":"{schema}","a":{{"d":"EATT","i":"{holder}","dt":"2026-01-01T00:00:00Z"{exp},"role":"researcher"}}}}"#
        )
    }

    fn proof(acdc: String, issuer: &str) -> PresentedCredential {
        PresentedCredential {
            acdc,
            issuer_cesr: MockBridge::issuer_sig(issuer),
            disclosed: vec!["role".into()],
        }
    }

    fn policy(rev: RevocationCheck) -> PolicyConfig {
        PolicyConfig {
            mode: crate::config::PolicyMode::Credential,
            schema_said: Some(SCHEMA.into()),
            issuer_aid: Some(ISSUER.into()),
            issuer_oobi: Some("[]".into()),
            revocation_check: rev,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_good_passport_passes_and_reports_expiry() {
        let bridge = MockBridge::new();
        let p = proof(
            acdc(
                "ECRED",
                ISSUER,
                SCHEMA,
                HOLDER,
                Some("2099-01-01T00:00:00Z"),
            ),
            ISSUER,
        );
        let ok = verify_presented(&bridge, &policy(RevocationCheck::IfKnown), HOLDER, &p)
            .await
            .unwrap();
        assert_eq!(ok.said, "ECRED");
        assert_eq!(ok.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert!(expiry_ts(ok.expires_at.as_deref()).unwrap() > chrono::Utc::now().timestamp());
    }

    #[tokio::test]
    async fn holder_schema_issuer_and_signature_mismatches_are_denied() {
        let bridge = MockBridge::new();
        let pol = policy(RevocationCheck::Off);
        let cases = [
            (
                proof(acdc("E1", ISSUER, SCHEMA, "EOTHER", None), ISSUER),
                "issued to EOTHER",
            ),
            (
                proof(acdc("E2", ISSUER, "EWRONG", HOLDER, None), ISSUER),
                "expected OCA bundle",
            ),
            (
                proof(acdc("E3", "EFAKE", SCHEMA, HOLDER, None), "EFAKE"),
                "expected authority",
            ),
            (
                proof(acdc("E4", ISSUER, SCHEMA, HOLDER, None), "EFAKE"),
                "signature check failed",
            ),
            (
                proof(acdc("EBAD5", ISSUER, SCHEMA, HOLDER, None), ISSUER),
                "binding check failed",
            ),
            (
                proof(
                    acdc("E6", ISSUER, SCHEMA, HOLDER, Some("2000-01-01T00:00:00Z")),
                    ISSUER,
                ),
                "validity check failed",
            ),
        ];
        for (p, needle) in cases {
            let err = verify_presented(&bridge, &pol, HOLDER, &p)
                .await
                .unwrap_err();
            assert!(err.contains(needle), "expected '{needle}' in '{err}'");
        }
        let mut bare = proof(acdc("E7", ISSUER, SCHEMA, HOLDER, None), ISSUER);
        bare.issuer_cesr.clear();
        assert!(verify_presented(&bridge, &pol, HOLDER, &bare)
            .await
            .unwrap_err()
            .contains("no issuer signature"));
    }

    #[tokio::test]
    async fn revocation_policy_matrix() {
        let bridge = MockBridge::new();
        let p = proof(acdc("ECRED", ISSUER, SCHEMA, HOLDER, None), ISSUER);
        // unknown registry answer
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::Off), HOLDER, &p)
                .await
                .is_ok()
        );
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::IfKnown), HOLDER, &p)
                .await
                .is_ok()
        );
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::Required), HOLDER, &p)
                .await
                .is_err()
        );
        bridge.set_revocation("ECRED", CheckState::Fail);
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::Off), HOLDER, &p)
                .await
                .is_ok()
        );
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::IfKnown), HOLDER, &p)
                .await
                .unwrap_err()
                .contains("revoked")
        );
        bridge.set_revocation("ECRED", CheckState::Pass);
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::Required), HOLDER, &p)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn daemon_outage_is_a_denial_not_a_pass() {
        let bridge = MockBridge::new();
        *bridge.fail_transport.lock().unwrap() = true;
        let p = proof(acdc("ECRED", ISSUER, SCHEMA, HOLDER, None), ISSUER);
        assert!(
            verify_presented(&bridge, &policy(RevocationCheck::Off), HOLDER, &p)
                .await
                .is_err()
        );
    }
}
