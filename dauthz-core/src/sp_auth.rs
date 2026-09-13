//! Shared vocabulary of the Cyfron service-provider auth ceremony.
//!
//! Every DauthZ resource server (the Gerrit plugin, Buildbot, the nginx
//! gate) speaks the same wire format to the Cyfron wallet. This module is
//! the single Rust definition of that format so the pieces cannot drift:
//!
//! * the `cyfron://auth?…` deep link the server hands to the browser,
//! * the JSON envelope the wallet signs (`cyfron-sp-auth/1` and `/2`),
//! * the body the wallet POSTs back to the server's `callback_url`,
//! * the proof shape a wallet uses when it presents a credential.
//!
//! None of this touches cryptography. Signatures are CESR attachments that
//! a KERI runtime (cyfron-serviced) verifies; here we only *split* a signed
//! stream into the JSON prefix and the attachments, and read fields out of
//! the prefix. We never re-serialize signed bytes: an ACDC's SAID and a
//! CESR signature both commit to the exact byte string, and a
//! `serde_json::Value` round-trip reorders object keys.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::challenge::CeremonyPurpose;
use crate::error::{DauthzError, Result};

/// Envelope version the wallet signs when it presents no credential.
pub const ENVELOPE_V1: &str = "cyfron-sp-auth/1";
/// Envelope version that additionally binds a presented credential SAID.
pub const ENVELOPE_V2: &str = "cyfron-sp-auth/2";

/// The JSON the wallet signs. Mirrors `build_payload` in
/// `cyfron-serviced/src/handlers/sp_auth.rs`. The verifier parses it out
/// of the signed CESR stream and compares it with what it issued.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpAuthEnvelope {
    pub v: String,
    pub nonce: String,
    pub entity_aid: String,
    #[serde(default)]
    pub disclosed_attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub tos_hash: Option<String>,
    /// Only present on `cyfron-sp-auth/2`: the SAID of the credential the
    /// holder is presenting, so the holder's signature binds it to this
    /// nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_credential_said: Option<String>,
}

impl SpAuthEnvelope {
    pub fn is_known_version(&self) -> bool {
        self.v == ENVELOPE_V1 || self.v == ENVELOPE_V2
    }
}

/// A credential as a wallet presents it: the canonical ACDC text, the
/// issuer's detached CESR signature over exactly those bytes, and the
/// attribute names the holder means to stand behind. This is the same
/// object Cyfron's Present dialog emits as QR/JSON text
/// (`useCredentials.ts::buildPresentation`), so a proof pasted into a page
/// and a proof carried in a callback are one format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentedCredential {
    pub acdc: String,
    pub issuer_cesr: String,
    #[serde(default)]
    pub disclosed: Vec<String>,
}

impl PresentedCredential {
    /// Parse a proof pasted by a user: either the `{acdc, issuer_cesr}`
    /// envelope or, for leniency, a bare ACDC (which then has no issuer
    /// signature and will fail verification with a clear reason).
    pub fn parse_proof(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| DauthzError::Envelope(format!("proof is not JSON: {e}")))?;
        if value.get("acdc").and_then(|v| v.as_str()).is_some() {
            return serde_json::from_str(trimmed)
                .map_err(|e| DauthzError::Envelope(format!("proof envelope: {e}")));
        }
        if value.get("d").is_some() && value.get("v").is_some() {
            return Ok(Self {
                acdc: trimmed.to_string(),
                issuer_cesr: String::new(),
                disclosed: Vec::new(),
            });
        }
        Err(DauthzError::Envelope(
            "proof is neither a {acdc, issuer_cesr} envelope nor an ACDC".into(),
        ))
    }

    fn acdc_value(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.acdc).ok()
    }

    /// The credential's SAID (`d`), read without re-serializing.
    pub fn said(&self) -> Option<String> {
        self.acdc_value()?.get("d")?.as_str().map(str::to_string)
    }

    /// The issuer AID (`i`).
    pub fn issuer_aid(&self) -> Option<String> {
        self.acdc_value()?.get("i")?.as_str().map(str::to_string)
    }

    /// The schema SAID (`s`) — for governance credentials, the OCA bundle SAID.
    pub fn schema_said(&self) -> Option<String> {
        self.acdc_value()?.get("s")?.as_str().map(str::to_string)
    }

    /// The holder AID (`a.i`).
    pub fn subject_aid(&self) -> Option<String> {
        self.acdc_value()?
            .get("a")?
            .get("i")?
            .as_str()
            .map(str::to_string)
    }

    /// The stream a KERI runtime verifies: ACDC bytes followed by the
    /// detached signature attachments.
    pub fn signed_stream(&self) -> String {
        let mut s = String::with_capacity(self.acdc.len() + self.issuer_cesr.len());
        s.push_str(&self.acdc);
        s.push_str(&self.issuer_cesr);
        s
    }
}

/// The body the wallet POSTs to `callback_url`. Every field but `nonce`
/// is optional on the wire so a `{"nonce", "decision":"deny"}` decline
/// parses too.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallbackBody {
    pub nonce: String,
    #[serde(default)]
    pub entity_oobi: Option<String>,
    #[serde(default)]
    pub signed_challenge: Option<String>,
    #[serde(default)]
    pub disclosed_attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub tos_hash: Option<String>,
    /// `"approve"` (default when absent) or `"deny"`.
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_credential: Option<PresentedCredential>,
}

impl CallbackBody {
    pub fn is_denied(&self) -> bool {
        self.decision.as_deref() == Some("deny")
    }
}

/// Everything that goes into a `cyfron://auth?…` deep link. Parameter
/// order and encoding match `ConnectInitServlet.buildDeepLink` in the
/// Gerrit plugin so wallets see one link shape from every server.
#[derive(Debug, Clone)]
pub struct DeepLinkParams<'a> {
    pub nonce: &'a str,
    pub service_aid: &'a str,
    pub service_oobi: &'a str,
    pub sp_name: &'a str,
    pub sp_origin: Option<&'a str>,
    pub sp_logo: Option<&'a str>,
    pub purpose: CeremonyPurpose,
    /// Comma-joined attribute names; only emitted for registration.
    pub requested_attrs: Option<&'a str>,
    pub callback_url: &'a str,
    pub invite: Option<&'a str>,
    pub tos_uri: Option<&'a str>,
    pub tos_hash: Option<&'a str>,
    /// `<schema_said>[@<issuer_aid>][,…]`; emitted when the server
    /// requires a credential presentation.
    pub requested_credentials: Option<&'a str>,
}

pub fn build_deep_link(scheme: &str, p: &DeepLinkParams<'_>) -> String {
    let mut out = format!("{scheme}://auth?");
    let mut push = |k: &str, v: &str| {
        out.push_str(k);
        out.push('=');
        out.push_str(&form_urlencode(v));
        out.push('&');
    };
    push("nonce", p.nonce);
    push("service_aid", p.service_aid);
    push("service_oobi", p.service_oobi);
    push("sp_name", p.sp_name);
    if let Some(o) = p.sp_origin {
        push("sp_origin", o);
    }
    if let Some(l) = p.sp_logo {
        push("sp_logo", l);
    }
    push(
        "purpose",
        match p.purpose {
            CeremonyPurpose::Registration => "registration",
            CeremonyPurpose::Identification => "identification",
        },
    );
    if p.purpose != CeremonyPurpose::Identification {
        if let Some(a) = p.requested_attrs {
            push("requested_attrs", a);
        }
    }
    push("callback_url", p.callback_url);
    if let Some(i) = p.invite {
        push("invite", i);
    }
    if let (Some(u), Some(h)) = (p.tos_uri, p.tos_hash) {
        push("tos_uri", u);
        push("tos_hash", h);
    }
    if let Some(c) = p.requested_credentials {
        push("requested_credentials", c);
    }
    if out.ends_with('&') {
        out.pop();
    }
    out
}

/// `application/x-www-form-urlencoded` encoding with the same alphabet as
/// Java's `URLEncoder.encode(s, UTF_8)`: `A-Za-z0-9.-*_` pass through,
/// space becomes `+`, everything else is `%XX` over UTF-8 bytes.
pub fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Split a signed CESR stream of the form `<json><attachments>` into its
/// two halves. The JSON prefix is located by parsing exactly one JSON
/// value; the remainder must be non-empty and start with the CESR count
/// code prefix `-`.
pub fn split_signed_json(stream: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut iter =
        serde_json::Deserializer::from_slice(stream).into_iter::<serde::de::IgnoredAny>();
    match iter.next() {
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            return Err(DauthzError::Envelope(format!(
                "signed stream does not start with JSON: {e}"
            )))
        }
        None => return Err(DauthzError::Envelope("signed stream is empty".into())),
    }
    let offset = iter.byte_offset();
    let (json, attachments) = stream.split_at(offset);
    if attachments.is_empty() {
        return Err(DauthzError::Envelope(
            "signed stream carries no signature attachments".into(),
        ));
    }
    if attachments[0] != b'-' {
        return Err(DauthzError::Envelope(
            "signed stream attachments do not start with a CESR count code".into(),
        ));
    }
    Ok((json, attachments))
}

/// Parse the envelope out of a signed stream.
pub fn parse_envelope(stream: &[u8]) -> Result<SpAuthEnvelope> {
    let (json, _) = split_signed_json(stream)?;
    serde_json::from_slice(json)
        .map_err(|e| DauthzError::Envelope(format!("envelope is not cyfron-sp-auth: {e}")))
}

/// The main AID named by an OOBI bag: the `cid` of the first end-role
/// entry, mirroring `DauthzCeremonyService.extractAidFromOobi`. Accepts a
/// JSON array of entries or a single object.
pub fn extract_aid_from_oobi(oobi_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(oobi_json.trim()).ok()?;
    let cid_of = |v: &serde_json::Value| v.get("cid")?.as_str().map(str::to_string);
    match value {
        serde_json::Value::Array(items) => items.iter().find_map(cid_of),
        serde_json::Value::Object(_) => cid_of(&value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OOBI: &str = r#"[{"eid":"BW1","scheme":"http","url":"http://w1/"},{"cid":"EMAIN","role":"witness","eid":"BW1"}]"#;

    #[test]
    fn deep_link_matches_gerrit_shape_and_encoding() {
        let link = build_deep_link(
            "cyfron",
            &DeepLinkParams {
                nonce: "n-1",
                service_aid: "ESVC",
                service_oobi: r#"[{"cid":"ESVC"}]"#,
                sp_name: "NextGen Docs",
                sp_origin: Some("https://docs.example.org"),
                sp_logo: None,
                purpose: CeremonyPurpose::Identification,
                requested_attrs: Some("name"),
                callback_url: "https://docs.example.org/dauthz/connect/callback",
                invite: None,
                tos_uri: None,
                tos_hash: None,
                requested_credentials: Some("ESCHEMA@EISSUER"),
            },
        );
        assert_eq!(
            link,
            "cyfron://auth?nonce=n-1&service_aid=ESVC&service_oobi=%5B%7B%22cid%22%3A%22ESVC%22%7D%5D\
             &sp_name=NextGen+Docs&sp_origin=https%3A%2F%2Fdocs.example.org&purpose=identification\
             &callback_url=https%3A%2F%2Fdocs.example.org%2Fdauthz%2Fconnect%2Fcallback\
             &requested_credentials=ESCHEMA%40EISSUER"
        );
        assert!(
            !link.contains("requested_attrs"),
            "login never asks for attributes"
        );
    }

    #[test]
    fn registration_link_carries_requested_attrs_and_tos_only_when_both_set() {
        let base = DeepLinkParams {
            nonce: "n",
            service_aid: "E",
            service_oobi: "[]",
            sp_name: "S",
            sp_origin: None,
            sp_logo: None,
            purpose: CeremonyPurpose::Registration,
            requested_attrs: Some("name,email"),
            callback_url: "http://cb",
            invite: Some("inv"),
            tos_uri: Some("http://tos"),
            tos_hash: None,
            requested_credentials: None,
        };
        let link = build_deep_link("cyfron", &base);
        assert!(link.contains("&requested_attrs=name%2Cemail&"));
        assert!(link.contains("&invite=inv"));
        assert!(
            !link.contains("tos_uri"),
            "tos_uri without tos_hash is dropped"
        );
        let with_hash = DeepLinkParams {
            tos_hash: Some("EH"),
            ..base
        };
        assert!(build_deep_link("cyfron", &with_hash)
            .ends_with("&tos_uri=http%3A%2F%2Ftos&tos_hash=EH"));
    }

    #[test]
    fn split_signed_json_finds_the_attachment_boundary() {
        let stream = br#"{"v":"cyfron-sp-auth/1","nonce":"n","entity_aid":"E","disclosed_attributes":{},"tos_hash":null}-VAi-AABAAxyz"#;
        let (json, att) = split_signed_json(stream).unwrap();
        assert_eq!(json, &stream[..stream.len() - "-VAi-AABAAxyz".len()]);
        assert_eq!(att, b"-VAi-AABAAxyz");
        let env = parse_envelope(stream).unwrap();
        assert_eq!(env.v, ENVELOPE_V1);
        assert_eq!(env.nonce, "n");
        assert!(env.presented_credential_said.is_none());
    }

    #[test]
    fn split_signed_json_rejects_missing_or_malformed_attachments() {
        assert!(split_signed_json(br#"{"a":1}"#).is_err());
        assert!(split_signed_json(br#"{"a":1}xyz"#).is_err());
        assert!(split_signed_json(b"not json").is_err());
        assert!(split_signed_json(b"").is_err());
    }

    #[test]
    fn v2_envelope_roundtrips_and_v1_has_no_credential_key() {
        let v2 = SpAuthEnvelope {
            v: ENVELOPE_V2.into(),
            nonce: "n".into(),
            entity_aid: "E".into(),
            disclosed_attributes: BTreeMap::new(),
            tos_hash: None,
            presented_credential_said: Some("ECRED".into()),
        };
        let text = serde_json::to_string(&v2).unwrap();
        assert!(text.contains("\"presented_credential_said\":\"ECRED\""));
        assert_eq!(serde_json::from_str::<SpAuthEnvelope>(&text).unwrap(), v2);

        let v1 = SpAuthEnvelope {
            v: ENVELOPE_V1.into(),
            presented_credential_said: None,
            ..v2
        };
        assert!(!serde_json::to_string(&v1)
            .unwrap()
            .contains("presented_credential_said"));
    }

    #[test]
    fn extract_aid_reads_the_first_cid() {
        assert_eq!(extract_aid_from_oobi(SAMPLE_OOBI).as_deref(), Some("EMAIN"));
        assert_eq!(
            extract_aid_from_oobi(r#"{"cid":"EONE","role":"witness"}"#).as_deref(),
            Some("EONE")
        );
        assert_eq!(
            extract_aid_from_oobi(r#"[{"eid":"B","scheme":"http","url":"u"}]"#),
            None
        );
        assert_eq!(extract_aid_from_oobi("garbage"), None);
    }

    #[test]
    fn callback_body_accepts_a_bare_decline() {
        let body: CallbackBody =
            serde_json::from_str(r#"{"nonce":"n","decision":"deny"}"#).unwrap();
        assert!(body.is_denied());
        assert!(body.entity_oobi.is_none());
    }

    #[test]
    fn presented_credential_reads_fields_without_reserializing() {
        let acdc = r#"{"v":"ACDC10JSON0000fb_","d":"ECRED","i":"EISS","ri":"EREG","s":"ESCH","a":{"d":"EATT","i":"EHOLD","dt":"2026-01-01T00:00:00Z","role":"researcher"}}"#;
        let proof = format!(
            r#"{{"acdc":{},"issuer_cesr":"-AABsig","disclosed":["role"]}}"#,
            serde_json::to_string(acdc).unwrap()
        );
        let p = PresentedCredential::parse_proof(&proof).unwrap();
        assert_eq!(p.acdc, acdc, "container text is carried verbatim");
        assert_eq!(p.said().as_deref(), Some("ECRED"));
        assert_eq!(p.issuer_aid().as_deref(), Some("EISS"));
        assert_eq!(p.schema_said().as_deref(), Some("ESCH"));
        assert_eq!(p.subject_aid().as_deref(), Some("EHOLD"));
        assert_eq!(p.signed_stream(), format!("{acdc}-AABsig"));

        let bare = PresentedCredential::parse_proof(acdc).unwrap();
        assert!(bare.issuer_cesr.is_empty());
        assert!(PresentedCredential::parse_proof(r#"{"foo":1}"#).is_err());
    }
}
