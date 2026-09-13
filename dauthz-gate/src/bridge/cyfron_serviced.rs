//! HTTP implementation of [`KeriBridge`] against `cyfron-serviced`, wire
//! compatible with the Gerrit plugin's `CyfronServicedBridge.java`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use super::*;

#[derive(Debug, Clone, Deserialize)]
struct EndpointFile {
    url: String,
    token: String,
}

pub struct CyfronServicedBridge {
    client: reqwest::Client,
    base_url: Mutex<String>,
    token: Mutex<String>,
    /// Set when the token came from the file (re-read on 401).
    endpoint_file: Option<PathBuf>,
    explicit_url: Option<String>,
    alias: Mutex<String>,
}

impl CyfronServicedBridge {
    /// `url` + `token` win; otherwise `endpoint_file` supplies both (the
    /// daemon writes it on start). An explicit `url` overrides the file's
    /// loopback URL, which is what a sidecar on a docker network needs.
    pub fn from_config(
        url: Option<&str>,
        token: Option<&str>,
        endpoint_file: Option<&Path>,
        timeout: Duration,
        alias: &str,
    ) -> Result<Self, BridgeError> {
        let (base_url, token_value, file) = match (url, token, endpoint_file) {
            (Some(u), Some(t), _) if !t.trim().is_empty() => (u.to_string(), t.to_string(), None),
            (u, _, Some(f)) => {
                let ep = read_endpoint_file(f)?;
                (
                    u.map(str::to_string).unwrap_or(ep.url),
                    ep.token,
                    Some(f.to_path_buf()),
                )
            }
            _ => {
                return Err(BridgeError::Config(
                    "set cyfron.url + cyfron.token, or cyfron.endpoint_file".into(),
                ))
            }
        };
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .build()
            .map_err(|e| BridgeError::Config(e.to_string()))?;
        Ok(Self {
            client,
            base_url: Mutex::new(base_url.trim_end_matches('/').to_string()),
            token: Mutex::new(token_value),
            endpoint_file: file,
            explicit_url: url.map(str::to_string),
            alias: Mutex::new(alias.to_string()),
        })
    }

    fn refresh_token_from_file(&self) -> bool {
        let Some(f) = &self.endpoint_file else {
            return false;
        };
        match read_endpoint_file(f) {
            Ok(ep) => {
                *self.token.lock().unwrap() = ep.token;
                if self.explicit_url.is_none() {
                    *self.base_url.lock().unwrap() = ep.url.trim_end_matches('/').to_string();
                }
                true
            }
            Err(e) => {
                tracing::warn!("could not re-read {}: {e}", f.display());
                false
            }
        }
    }

    async fn send(
        &self,
        build: impl Fn(&reqwest::Client, &str, &str) -> reqwest::RequestBuilder,
    ) -> Result<(u16, String), BridgeError> {
        for attempt in 0..2 {
            let (base, token) = (
                self.base_url.lock().unwrap().clone(),
                self.token.lock().unwrap().clone(),
            );
            let resp = build(&self.client, &base, &token)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))?;
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 401 && attempt == 0 && self.refresh_token_from_file() {
                tracing::info!("daemon token rejected; retrying with the token from endpoint.json");
                continue;
            }
            return Ok((status, body));
        }
        unreachable!()
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, BridgeError> {
        let p = path.to_string();
        let (status, body) = self.send(|c, base, _| c.get(format!("{base}{p}"))).await?;
        match status {
            200..=299 => serde_json::from_str(&body)
                .map(Some)
                .map_err(|e| BridgeError::Parse(e.to_string())),
            404 => Ok(None),
            _ => Err(BridgeError::Status { status, body }),
        }
    }

    async fn post_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<(u16, String), BridgeError> {
        let p = path.to_string();
        self.send(|c, base, _| c.post(format!("{base}{p}")).json(&payload))
            .await
    }

    async fn post_ok<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<T, BridgeError> {
        let (status, body) = self.post_json(path, payload).await?;
        if !(200..=299).contains(&status) {
            return Err(BridgeError::Status { status, body });
        }
        serde_json::from_str(&body).map_err(|e| BridgeError::Parse(format!("{e}: {body}")))
    }
}

fn read_endpoint_file(path: &Path) -> Result<EndpointFile, BridgeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| BridgeError::Config(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| BridgeError::Config(format!("{} is not {{url, token}}: {e}", path.display())))
}

#[async_trait]
impl KeriBridge for CyfronServicedBridge {
    fn alias(&self) -> String {
        self.alias.lock().unwrap().clone()
    }

    fn set_alias(&self, alias: &str) {
        *self.alias.lock().unwrap() = alias.to_string();
    }

    async fn identifier_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentifierInfo>, BridgeError> {
        let q = dauthz_core::sp_auth::form_urlencode(alias);
        self.get_json(&format!("/keri/identifier-by-alias?alias={q}"))
            .await
    }

    async fn list_identifiers(&self) -> Result<Vec<IdentifierInfo>, BridgeError> {
        Ok(self
            .get_json::<Vec<IdentifierInfo>>("/identifiers")
            .await?
            .unwrap_or_default())
    }

    async fn create_identifier(
        &self,
        req: &CreateIdentifier,
    ) -> Result<IdentifierInfo, BridgeError> {
        let payload = serde_json::to_value(req).map_err(|e| BridgeError::Parse(e.to_string()))?;
        self.post_ok("/identifiers", payload).await
    }

    async fn resolve_oobi(&self, oobi: &serde_json::Value) -> Result<ResolveOutcome, BridgeError> {
        let payload = serde_json::json!({ "alias": self.alias(), "oobi": oobi });
        self.post_ok("/keri/resolve-oobi", payload).await
    }

    async fn verify_introduction(
        &self,
        main_aid: &str,
        cesr: &str,
    ) -> Result<IntroductionVerdict, BridgeError> {
        let payload = serde_json::json!({ "aid": main_aid, "cesr": cesr });
        let (status, body) = self.post_json("/keri/verify-introduction", payload).await?;
        if !(200..=299).contains(&status) {
            tracing::warn!(status, "verify-introduction refused: {body}");
            return Ok(IntroductionVerdict::default());
        }
        Ok(parse_introduction_response(&body))
    }

    async fn sign(&self, payload: &str) -> Result<String, BridgeError> {
        #[derive(Deserialize)]
        struct Signed {
            cesr: String,
        }
        let body = serde_json::json!({ "alias": self.alias(), "payload": payload });
        let signed: Signed = self.post_ok("/keri/sign-cesr", body).await?;
        Ok(signed.cesr)
    }

    async fn verify_credential(
        &self,
        acdc: &str,
        issuer_cesr: &str,
    ) -> Result<CredentialVerification, BridgeError> {
        let payload = serde_json::json!({ "acdc": acdc, "issuer_cesr": issuer_cesr });
        self.post_ok("/credentials/verify", payload).await
    }
}
