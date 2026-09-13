//! What the gate asserts about a signed envelope *before* asking the
//! daemon anything. The Gerrit plugin skips these; here the nonce, the
//! main AID and (in credential mode) the presented SAID are all bound.

use dauthz_core::sp_auth::{self, CallbackBody, SpAuthEnvelope, ENVELOPE_V2};

pub fn check_envelope(
    body: &CallbackBody,
    expected_nonce: &str,
    main_aid: &str,
) -> Result<SpAuthEnvelope, String> {
    let signed = body
        .signed_challenge
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing signed_challenge".to_string())?;
    let envelope = sp_auth::parse_envelope(signed.as_bytes()).map_err(|e| e.to_string())?;
    if !envelope.is_known_version() {
        return Err(format!("unsupported envelope version {}", envelope.v));
    }
    if envelope.nonce != expected_nonce {
        return Err("signed nonce does not match the challenge".into());
    }
    if envelope.entity_aid != main_aid {
        return Err("signed entity_aid does not match the presented OOBI".into());
    }
    if let Some(cred) = &body.presented_credential {
        if envelope.v != ENVELOPE_V2 {
            return Err("a presented credential requires a cyfron-sp-auth/2 envelope".into());
        }
        let said = cred
            .said()
            .ok_or_else(|| "presented credential has no SAID".to_string())?;
        if envelope.presented_credential_said.as_deref() != Some(said.as_str()) {
            return Err("signed envelope does not bind the presented credential".into());
        }
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dauthz_core::sp_auth::{PresentedCredential, ENVELOPE_V1};
    use std::collections::BTreeMap;

    fn envelope(v: &str, nonce: &str, aid: &str, said: Option<&str>) -> String {
        let e = SpAuthEnvelope {
            v: v.into(),
            nonce: nonce.into(),
            entity_aid: aid.into(),
            disclosed_attributes: BTreeMap::new(),
            tos_hash: None,
            presented_credential_said: said.map(str::to_string),
        };
        format!("{}-MOCK:{aid}", serde_json::to_string(&e).unwrap())
    }

    fn body(signed: &str) -> CallbackBody {
        CallbackBody {
            nonce: "n".into(),
            signed_challenge: Some(signed.into()),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_matching_v1() {
        let e = check_envelope(&body(&envelope(ENVELOPE_V1, "n", "EA", None)), "n", "EA").unwrap();
        assert_eq!(e.v, ENVELOPE_V1);
    }

    #[test]
    fn rejects_nonce_and_aid_mismatch_and_bad_version() {
        assert!(check_envelope(
            &body(&envelope(ENVELOPE_V1, "other", "EA", None)),
            "n",
            "EA"
        )
        .is_err());
        assert!(check_envelope(&body(&envelope(ENVELOPE_V1, "n", "EB", None)), "n", "EA").is_err());
        assert!(check_envelope(
            &body(&envelope("cyfron-sp-auth/9", "n", "EA", None)),
            "n",
            "EA"
        )
        .is_err());
        assert!(check_envelope(
            &CallbackBody {
                nonce: "n".into(),
                ..Default::default()
            },
            "n",
            "EA"
        )
        .is_err());
    }

    #[test]
    fn presented_credential_must_be_bound_by_a_v2_envelope() {
        let cred = PresentedCredential {
            acdc: r#"{"v":"ACDC","d":"ECRED","i":"EI","s":"ES","a":{"i":"EA"}}"#.into(),
            issuer_cesr: "-x".into(),
            disclosed: vec![],
        };
        let mut b = body(&envelope(ENVELOPE_V1, "n", "EA", None));
        b.presented_credential = Some(cred.clone());
        assert!(check_envelope(&b, "n", "EA")
            .unwrap_err()
            .contains("cyfron-sp-auth/2"));
        b.signed_challenge = Some(envelope(ENVELOPE_V2, "n", "EA", Some("EOTHER")));
        assert!(check_envelope(&b, "n", "EA")
            .unwrap_err()
            .contains("does not bind"));
        b.signed_challenge = Some(envelope(ENVELOPE_V2, "n", "EA", Some("ECRED")));
        assert!(check_envelope(&b, "n", "EA").is_ok());
    }
}
