//! Who may enter once the signature is good.

use crate::config::{PolicyConfig, PolicyMode};

/// The AID-level decision. Credential mode returns `Ok` here and defers to
/// [`crate::credential`] for the presentation.
pub fn evaluate_aid(policy: &PolicyConfig, main_aid: &str) -> Result<(), String> {
    match policy.mode {
        PolicyMode::Open | PolicyMode::Credential => Ok(()),
        PolicyMode::Allowlist => {
            if policy.allowed_aids.iter().any(|a| a == main_aid) {
                Ok(())
            } else {
                Err("AID is not on the allowlist".into())
            }
        }
    }
}

/// Re-check on every `auth_request`: cheap live revocation for the facts
/// the gate can decide alone.
pub fn still_allowed(policy: &PolicyConfig, main_aid: &str, cred_said: Option<&str>) -> bool {
    match policy.mode {
        PolicyMode::Open => true,
        PolicyMode::Allowlist => policy.allowed_aids.iter().any(|a| a == main_aid),
        PolicyMode::Credential => cred_said.is_some(),
    }
}

pub fn requirement_text(policy: &PolicyConfig) -> Option<String> {
    if policy.mode != PolicyMode::Credential {
        return policy.requirement_text.clone();
    }
    Some(policy.requirement_text.clone().unwrap_or_else(|| {
        format!(
            "Access requires a credential issued by {} (schema {}).",
            policy
                .issuer_aid
                .as_deref()
                .unwrap_or("the configured authority"),
            policy.schema_said.as_deref().unwrap_or("?")
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_and_credential_modes() {
        let mut p = PolicyConfig {
            allowed_aids: vec!["EA".into()],
            ..Default::default()
        };
        assert!(evaluate_aid(&p, "EA").is_ok());
        assert!(evaluate_aid(&p, "EB").is_err());
        assert!(still_allowed(&p, "EA", None));
        assert!(!still_allowed(&p, "EB", None));
        p.mode = PolicyMode::Credential;
        assert!(evaluate_aid(&p, "EB").is_ok());
        assert!(!still_allowed(&p, "EB", None));
        assert!(still_allowed(&p, "EB", Some("ECRED")));
        p.mode = PolicyMode::Open;
        assert!(still_allowed(&p, "anyone", None));
    }
}
