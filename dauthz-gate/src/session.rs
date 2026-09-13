//! Stateless session cookies: `base64url(claims JSON) . base64url(HMAC-SHA256)`.
//!
//! The gate keeps no session table. Every request nginx forwards to
//! `/auth` carries the cookie, and the gate re-validates the MAC and the
//! expiry. Revocation before expiry therefore only exists for facts the
//! gate can re-check live (the allowlist); everything else waits for the
//! TTL, which is why the default is twelve hours rather than thirty days.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionClaims {
    /// Claims format version.
    pub v: u8,
    /// Random session id, for logs.
    pub sid: String,
    /// The user's main AID (account key).
    pub aid: String,
    /// The AID that actually signed the challenge (device or main AID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_aid: Option<String>,
    /// SAID of the credential this session presented, when policy needed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_said: Option<String>,
    /// Unix seconds.
    pub iat: i64,
    pub exp: i64,
}

impl SessionClaims {
    pub fn new(aid: &str, signer_aid: Option<&str>, ttl_secs: u64) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            v: 1,
            sid: uuid::Uuid::new_v4().to_string(),
            aid: aid.to_string(),
            signer_aid: signer_aid.map(str::to_string),
            cred_said: None,
            iat: now,
            exp: now + ttl_secs as i64,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.exp
    }

    /// Cap the expiry (used to bound a session by its credential's `exp`).
    pub fn cap_exp(&mut self, not_after: i64) {
        if not_after < self.exp {
            self.exp = not_after;
        }
    }
}

#[derive(Clone)]
pub struct CookieCodec {
    key: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CookieError {
    #[error("malformed cookie")]
    Malformed,
    #[error("bad signature")]
    BadSignature,
    #[error("expired")]
    Expired,
}

impl CookieCodec {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self {
            key: key.as_ref().to_vec(),
        }
    }

    pub fn encode(&self, claims: &SessionClaims) -> String {
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(body.as_bytes());
        let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{body}.{tag}")
    }

    pub fn decode(&self, cookie: &str) -> Result<SessionClaims, CookieError> {
        let (body, tag) = cookie.split_once('.').ok_or(CookieError::Malformed)?;
        let given = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| CookieError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(body.as_bytes());
        let expected = mac.finalize().into_bytes();
        if given.len() != expected.len() || given.ct_eq(&expected).unwrap_u8() != 1 {
            return Err(CookieError::BadSignature);
        }
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| CookieError::Malformed)?;
        let claims: SessionClaims =
            serde_json::from_slice(&json).map_err(|_| CookieError::Malformed)?;
        if claims.is_expired() {
            return Err(CookieError::Expired);
        }
        Ok(claims)
    }
}

/// Load the cookie secret from config or a persisted file, generating one
/// on first start. Returns the raw key bytes.
pub fn load_or_create_secret(
    explicit: Option<&str>,
    path: &std::path::Path,
) -> anyhow::Result<Vec<u8>> {
    if let Some(s) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(s.as_bytes().to_vec());
    }
    if let Ok(existing) = std::fs::read(path) {
        if existing.len() >= 32 {
            return Ok(existing);
        }
    }
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let codec = CookieCodec::new("secret-key");
        let claims = SessionClaims::new("EAID", Some("EDEV"), 60);
        let cookie = codec.encode(&claims);
        assert_eq!(codec.decode(&cookie).unwrap(), claims);

        let (body, tag) = cookie.split_once('.').unwrap();
        let other = SessionClaims {
            aid: "EEVIL".into(),
            ..claims.clone()
        };
        let forged_body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&other).unwrap());
        assert_eq!(
            codec.decode(&format!("{forged_body}.{tag}")),
            Err(CookieError::BadSignature)
        );
        assert_eq!(codec.decode(body), Err(CookieError::Malformed));
        assert_eq!(
            CookieCodec::new("other").decode(&cookie),
            Err(CookieError::BadSignature)
        );
    }

    #[test]
    fn expired_claims_are_rejected() {
        let codec = CookieCodec::new("k");
        let mut claims = SessionClaims::new("E", None, 60);
        claims.exp = chrono::Utc::now().timestamp() - 1;
        assert_eq!(
            codec.decode(&codec.encode(&claims)),
            Err(CookieError::Expired)
        );
    }

    #[test]
    fn secret_is_generated_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("cookie-secret");
        let a = load_or_create_secret(None, &path).unwrap();
        let b = load_or_create_secret(None, &path).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_eq!(
            load_or_create_secret(Some("fixed"), &path).unwrap(),
            b"fixed"
        );
    }
}
