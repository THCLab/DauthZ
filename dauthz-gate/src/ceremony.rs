//! The four-step ceremony (init → callback → status → finish) plus the
//! credential presentation step, independent of HTTP framing so it can be
//! driven from tests with a mock bridge.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dauthz_core::sp_auth::{build_deep_link, CallbackBody, DeepLinkParams, PresentedCredential};
use dauthz_core::{CeremonyPurpose, Challenge};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::bridge::KeriBridge;
use crate::config::{Config, PolicyMode, Presentation};
use crate::credential;
use crate::envelope::check_envelope;
use crate::identity::ServiceIdentity;
use crate::policy;
use crate::session::{CookieCodec, SessionClaims};
use crate::store::{ChallengeStore, PendingSessionStore, PendingState};

/// Everything the HTTP layer shares.
pub struct Gate {
    pub config: Config,
    pub bridge: Arc<dyn KeriBridge>,
    pub identity: RwLock<Option<ServiceIdentity>>,
    pub challenges: Arc<ChallengeStore>,
    pub pending: Arc<PendingSessionStore>,
    pub codec: CookieCodec,
    pub started_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitResponse {
    pub nonce: String,
    pub deep_link: String,
    pub status_url: String,
    pub finish_url: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handoff_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub needs_credential: bool,
    pub new_account: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackOutcome {
    /// User declined in the wallet.
    Declined,
    /// Signature and policy accepted; `needs_credential` means the page
    /// presentation step still has to run before `/auth` says yes.
    Authenticated { aid: String, needs_credential: bool },
    /// Refused; `status` is the HTTP status to answer with.
    Rejected { status: u16, reason: String },
}

#[derive(Debug, Clone)]
pub struct FinishOutcome {
    pub claims: SessionClaims,
    pub return_to: String,
    pub needs_credential: bool,
}

impl Gate {
    pub fn new(config: Config, bridge: Arc<dyn KeriBridge>, codec: CookieCodec) -> Self {
        Self {
            config,
            bridge,
            identity: RwLock::new(None),
            challenges: Arc::new(ChallengeStore::default()),
            pending: Arc::new(PendingSessionStore::default()),
            codec,
            started_at: Utc::now(),
        }
    }

    pub async fn identity(&self) -> Option<ServiceIdentity> {
        self.identity.read().await.clone()
    }

    pub async fn set_identity(&self, id: ServiceIdentity) {
        *self.identity.write().await = Some(id);
    }

    fn ttl(&self) -> Duration {
        Duration::from_secs(self.config.challenge_ttl_secs)
    }

    /// Does the deep link ask the wallet to present a credential?
    fn inline_presentation(&self) -> bool {
        self.config.requires_credential()
            && matches!(
                self.config.policy.presentation,
                Presentation::Inline | Presentation::Both
            )
    }

    /// May a session without a credential be completed on the `/present` page?
    fn page_presentation(&self) -> bool {
        matches!(
            self.config.policy.presentation,
            Presentation::Page | Presentation::Both
        )
    }

    /// Resolve the issuer's OOBI on the daemon so its KEL is available for
    /// credential signature checks. Best effort; logged.
    pub async fn refresh_issuer_kel(&self) {
        let Some(oobi) = self.config.policy.issuer_oobi.as_deref() else {
            return;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(oobi) else {
            return;
        };
        match self.bridge.resolve_oobi(&value).await {
            Ok(out) if out.kel_errors.is_empty() => {
                tracing::info!(resolved = out.resolved, "issuer OOBI resolved")
            }
            Ok(out) => tracing::warn!("issuer OOBI resolved with KEL errors: {:?}", out.kel_errors),
            Err(e) => tracing::warn!("issuer OOBI resolution failed: {e}"),
        }
    }

    pub async fn init(&self, return_to: &str) -> Result<InitResponse, String> {
        let identity = self.identity().await.ok_or("service identity not ready")?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.config.challenge_ttl_secs as i64);
        self.challenges.store(Challenge {
            nonce: nonce.clone(),
            service_aid: identity.aid.clone(),
            msgbox_oobi: String::new(),
            service_oobi: identity.oobi.clone(),
            timestamp: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            purpose: CeremonyPurpose::Identification,
        });
        // The pending session outlives the challenge a little so a slow
        // browser poll still sees the final state.
        self.pending
            .create(&nonce, return_to, self.ttl() + Duration::from_secs(120));

        let requested = if self.inline_presentation() {
            Some(format!(
                "{}@{}",
                self.config.policy.schema_said.as_deref().unwrap_or(""),
                self.config.policy.issuer_aid.as_deref().unwrap_or("")
            ))
        } else {
            None
        };
        let callback_url = self.config.callback_url();
        let origin = self.config.origin();
        let deep_link = build_deep_link(
            &self.config.cyfron.deep_link_scheme,
            &DeepLinkParams {
                nonce: &nonce,
                service_aid: &identity.aid,
                service_oobi: &identity.oobi,
                sp_name: &self.config.site.name,
                sp_origin: Some(&origin),
                sp_logo: self.config.site.logo_url.as_deref(),
                purpose: CeremonyPurpose::Identification,
                requested_attrs: None,
                callback_url: &callback_url,
                invite: None,
                tos_uri: None,
                tos_hash: None,
                requested_credentials: requested.as_deref(),
            },
        );
        Ok(InitResponse {
            status_url: format!(
                "{}?nonce={}",
                self.config.prefixed("/connect/status"),
                nonce
            ),
            finish_url: self.config.prefixed("/connect/finish"),
            nonce,
            deep_link,
            expires_at: expires_at.to_rfc3339(),
        })
    }

    pub async fn callback(&self, body: CallbackBody) -> CallbackOutcome {
        let nonce = body.nonce.clone();
        if nonce.is_empty() {
            return CallbackOutcome::Rejected {
                status: 400,
                reason: "missing nonce".into(),
            };
        }
        let reject = |status: u16, reason: &str| {
            self.pending.deny(&nonce, reason);
            self.challenges.consume(&nonce);
            CallbackOutcome::Rejected {
                status,
                reason: reason.to_string(),
            }
        };

        if body.is_denied() {
            self.pending.deny(&nonce, "user declined");
            self.challenges.consume(&nonce);
            return CallbackOutcome::Declined;
        }

        let Some(challenge) = self.challenges.get(&nonce) else {
            return CallbackOutcome::Rejected {
                status: 403,
                reason: "unknown challenge nonce".into(),
            };
        };
        match crate::store::parse_ts(&challenge.expires_at) {
            Some(exp) if exp > Utc::now() => {}
            _ => return reject(403, "challenge expired"),
        }
        match self.pending.get(&nonce) {
            Some(s) if s.state == PendingState::Pending => {}
            _ => return reject(403, "session is no longer pending"),
        }

        let Some(entity_oobi) = body.entity_oobi.as_deref().filter(|s| !s.is_empty()) else {
            return reject(400, "missing entity_oobi");
        };
        let Some(main_aid) = dauthz_core::sp_auth::extract_aid_from_oobi(entity_oobi) else {
            return reject(400, "entity_oobi names no AID (cid)");
        };

        // Envelope binding: nonce, AID and presented SAID, before any daemon call.
        let envelope = match check_envelope(&body, &nonce, &main_aid) {
            Ok(e) => e,
            Err(reason) => return reject(403, &reason),
        };

        // Make the user's KEL available; a failure here surfaces as a
        // verification failure below, which is the honest outcome.
        if let Ok(oobi_value) = serde_json::from_str::<serde_json::Value>(entity_oobi) {
            if let Err(e) = self.bridge.resolve_oobi(&oobi_value).await {
                tracing::warn!(nonce = %nonce, "entity OOBI resolution failed: {e}");
            }
        }

        let signed = body.signed_challenge.as_deref().unwrap_or_default();
        let verdict = match self.bridge.verify_introduction(&main_aid, signed).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(nonce = %nonce, "verify-introduction unavailable: {e}");
                return reject(403, "signature verification failed");
            }
        };
        if !verdict.accepted() {
            tracing::warn!(nonce = %nonce, aid = %main_aid, ?verdict, "introduction refused");
            return reject(403, "signature verification failed");
        }
        tracing::info!(nonce = %nonce, aid = %main_aid, signer = ?verdict.signer_aid, v = %envelope.v, "challenge verified");

        if let Err(reason) = policy::evaluate_aid(&self.config.policy, &main_aid) {
            return reject(403, &reason);
        }

        let mut claims = SessionClaims::new(
            &main_aid,
            verdict.signer_aid.as_deref(),
            self.config.cookie.ttl_secs,
        );
        let mut needs_credential = false;
        if self.config.requires_credential() {
            match &body.presented_credential {
                Some(presented) => {
                    match credential::verify_presented(
                        self.bridge.as_ref(),
                        &self.config.policy,
                        &main_aid,
                        presented,
                    )
                    .await
                    {
                        Ok(passport) => {
                            claims.cred_said = Some(passport.said);
                            if let Some(ts) = credential::expiry_ts(passport.expires_at.as_deref())
                            {
                                claims.cap_exp(ts);
                            }
                        }
                        Err(reason) => {
                            // A stale issuer KEL is the common cause; refresh and retry once.
                            self.refresh_issuer_kel().await;
                            match credential::verify_presented(
                                self.bridge.as_ref(),
                                &self.config.policy,
                                &main_aid,
                                presented,
                            )
                            .await
                            {
                                Ok(passport) => {
                                    claims.cred_said = Some(passport.said);
                                    if let Some(ts) =
                                        credential::expiry_ts(passport.expires_at.as_deref())
                                    {
                                        claims.cap_exp(ts);
                                    }
                                }
                                Err(_) => return reject(403, &reason),
                            }
                        }
                    }
                }
                None if self.page_presentation() => needs_credential = true,
                None => return reject(403, "credential required"),
            }
        }

        self.challenges.consume(&nonce);
        if self
            .pending
            .approve(&nonce, claims, needs_credential)
            .is_none()
        {
            return CallbackOutcome::Rejected {
                status: 403,
                reason: "session is no longer pending".into(),
            };
        }
        CallbackOutcome::Authenticated {
            aid: main_aid,
            needs_credential,
        }
    }

    pub fn status(&self, nonce: &str) -> StatusResponse {
        let base = StatusResponse {
            state: "expired",
            handoff_token: None,
            reason: None,
            needs_credential: false,
            new_account: false,
        };
        let Some(session) = self.pending.get(nonce) else {
            return base;
        };
        if session.expires_at <= Utc::now() {
            return base;
        }
        match session.state {
            PendingState::Pending => StatusResponse {
                state: "pending",
                ..base
            },
            PendingState::Approved => StatusResponse {
                state: "approved",
                handoff_token: session.handoff_token,
                needs_credential: session.needs_credential,
                ..base
            },
            PendingState::Denied => StatusResponse {
                state: "denied",
                reason: session.failure_reason,
                ..base
            },
        }
    }

    pub fn finish(&self, token: &str) -> Option<FinishOutcome> {
        let session = self.pending.consume_handoff(token)?;
        Some(FinishOutcome {
            claims: session.claims?,
            return_to: session.return_to,
            needs_credential: session.needs_credential,
        })
    }

    /// The page presentation step: attach a verified passport to an
    /// AID-authenticated session.
    pub async fn present(
        &self,
        claims: &SessionClaims,
        proof: &PresentedCredential,
    ) -> Result<SessionClaims, String> {
        if !self.config.requires_credential() {
            return Err("this site does not require a credential".into());
        }
        if !self.page_presentation() {
            return Err(
                "credential presentation on this page is disabled; present it from the wallet"
                    .into(),
            );
        }
        let passport = match credential::verify_presented(
            self.bridge.as_ref(),
            &self.config.policy,
            &claims.aid,
            proof,
        )
        .await
        {
            Ok(p) => p,
            Err(first) => {
                self.refresh_issuer_kel().await;
                credential::verify_presented(
                    self.bridge.as_ref(),
                    &self.config.policy,
                    &claims.aid,
                    proof,
                )
                .await
                .map_err(|_| first)?
            }
        };
        let mut updated = claims.clone();
        updated.cred_said = Some(passport.said);
        if let Some(ts) = credential::expiry_ts(passport.expires_at.as_deref()) {
            updated.cap_exp(ts);
        }
        Ok(updated)
    }

    /// The `auth_request` decision.
    pub fn authorize(&self, claims: &SessionClaims) -> bool {
        policy::still_allowed(
            &self.config.policy,
            &claims.aid,
            claims.cred_said.as_deref(),
        )
    }

    pub fn policy_mode(&self) -> PolicyMode {
        self.config.policy.mode
    }
}
