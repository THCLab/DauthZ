use dauthz_core::challenge::{CeremonyPurpose, Challenge, ChallengeResponse, SessionToken};
use dauthz_core::{DauthzError, Result};

use reqwest::Client;

#[derive(Debug, Clone)]
pub struct Transport {
    http: Client,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            http: Client::new(),
        }
    }
}

impl Transport {
    pub async fn get_challenge(
        &self,
        service_url: &str,
        purpose: CeremonyPurpose,
    ) -> Result<Challenge> {
        let endpoint = match purpose {
            CeremonyPurpose::Registration => "register",
            CeremonyPurpose::Identification => "login",
        };
        let url = format!("{}/dauthz/{}", service_url.trim_end_matches('/'), endpoint);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| DauthzError::TransportError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DauthzError::TransportError(format!(
                "GET {} returned {}: {}",
                url, status, body
            )));
        }

        resp.json::<Challenge>()
            .await
            .map_err(|e| DauthzError::TransportError(e.to_string()))
    }

    pub async fn submit_response(
        &self,
        service_url: &str,
        response: ChallengeResponse,
    ) -> Result<SessionToken> {
        let url = format!("{}/dauthz/respond", service_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(&response)
            .send()
            .await
            .map_err(|e| DauthzError::TransportError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(DauthzError::TransportError(format!(
                "POST {} returned {}: {}",
                url, status, body
            )));
        }

        resp.json::<SessionToken>()
            .await
            .map_err(|e| DauthzError::TransportError(e.to_string()))
    }
}
