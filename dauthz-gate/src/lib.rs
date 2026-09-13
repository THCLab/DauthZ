//! `dauthz-gate`: an `auth_request` sidecar for nginx (or any forward-auth
//! proxy) that signs users in with their Cyfron KERI AID and, optionally,
//! a credential issued by a configured authority.
//!
//! The crate follows the DauthZ convention that no KERI cryptography lives
//! here: every signature check is delegated to a `cyfron-serviced` daemon
//! over HTTP through the [`bridge::KeriBridge`] trait, which tests replace
//! with a scripted mock.

pub mod bridge;
pub mod ceremony;
pub mod config;
pub mod credential;
pub mod envelope;
pub mod http;
pub mod identity;
pub mod policy;
pub mod session;
pub mod store;
