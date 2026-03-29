use std::future::Future;

use dauthz_core::challenge::{CeremonyPurpose, Challenge, ChallengeResponse, SessionToken};
use dauthz_core::Result;

use crate::transport::Transport;

#[derive(Debug)]
pub struct DauthzClient {
    transport: Transport,
}

impl Default for DauthzClient {
    fn default() -> Self {
        Self {
            transport: Transport::default(),
        }
    }
}

impl DauthzClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn request_challenge(
        &self,
        service_url: &str,
        purpose: CeremonyPurpose,
    ) -> Result<Challenge> {
        self.transport.get_challenge(service_url, purpose).await
    }

    pub async fn submit_response(
        &self,
        service_url: &str,
        response: ChallengeResponse,
    ) -> Result<SessionToken> {
        self.transport.submit_response(service_url, response).await
    }

    pub async fn register<F, Fut>(
        &self,
        service_url: &str,
        entity_aid: &str,
        entity_oobi: &str,
        sign_fn: F,
    ) -> Result<String>
    where
        F: Fn(&str) -> Fut,
        Fut: Future<Output = Result<String>>,
    {
        let challenge = self
            .request_challenge(service_url, CeremonyPurpose::Registration)
            .await?;
        let signed = sign_fn(&serde_json::to_string(&challenge)?).await?;
        let response = ChallengeResponse {
            entity_aid: entity_aid.to_string(),
            entity_oobi: entity_oobi.to_string(),
            nonce: challenge.nonce,
            signed_challenge: signed,
        };
        self.submit_response(service_url, response).await?;
        Ok(entity_aid.to_string())
    }

    pub async fn login<F, Fut>(
        &self,
        service_url: &str,
        entity_aid: &str,
        entity_oobi: &str,
        sign_fn: F,
    ) -> Result<SessionToken>
    where
        F: Fn(&str) -> Fut,
        Fut: Future<Output = Result<String>>,
    {
        let challenge = self
            .request_challenge(service_url, CeremonyPurpose::Identification)
            .await?;
        let signed = sign_fn(&serde_json::to_string(&challenge)?).await?;
        let response = ChallengeResponse {
            entity_aid: entity_aid.to_string(),
            entity_oobi: entity_oobi.to_string(),
            nonce: challenge.nonce,
            signed_challenge: signed,
        };
        self.submit_response(service_url, response).await
    }
}
