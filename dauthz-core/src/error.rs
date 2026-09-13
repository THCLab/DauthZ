use thiserror::Error;

#[derive(Debug, Error)]
pub enum DauthzError {
    #[error("dkms CLI error: {0}")]
    DkmsError(String),

    #[error("failed to parse dkms output: {0}")]
    ParseError(String),

    #[error("HTTP transport error: {0}")]
    TransportError(String),

    #[error("unknown challenge nonce")]
    UnknownChallenge,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("account not found")]
    AccountNotFound,

    #[error("account already exists for AID: {0}")]
    AccountAlreadyExists(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid ceremony state: {0}")]
    InvalidState(String),

    #[error("identifier not found: {0}")]
    IdentifierNotFound(String),

    #[error("malformed signed envelope: {0}")]
    Envelope(String),

    #[error("access denied by policy: {0}")]
    PolicyDenied(String),

    #[error("KERI bridge error: {0}")]
    Bridge(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DauthzError>;
