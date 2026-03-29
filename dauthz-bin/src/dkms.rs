use std::path::{Path, PathBuf};
use std::process::Stdio;

use dauthz_core::{DauthzError, Result};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Clone, Deserialize)]
pub struct AidInfo {
    pub aid: String,
    pub registry_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobiInfo {
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub eid: String,
    pub cid: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DkmsBridge {
    binary_path: PathBuf,
    alias: String,
    home_dir: PathBuf,
}

impl DkmsBridge {
    pub fn new(binary_path: &Path, alias: &str, home_dir: &Path) -> Self {
        Self {
            binary_path: binary_path.to_path_buf(),
            alias: alias.to_string(),
            home_dir: home_dir.to_path_buf(),
        }
    }

    async fn run(&self, args: &[&str]) -> Result<String> {
        eprint!("[dkms] {} {}", self.binary_path.display(), args.join(" "));
        let output = Command::new(&self.binary_path)
            .args(args)
            .env("HOME", &self.home_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| DauthzError::DkmsError(format!("failed to execute dkms: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            eprintln!(" -> FAILED");
            if !stderr.is_empty() {
                eprintln!("[dkms stderr] {stderr}");
            }
            return Err(DauthzError::DkmsError(stderr));
        }

        eprintln!(" -> OK");
        if !stdout.is_empty() {
            eprintln!("[dkms stdout] {stdout}");
        }
        Ok(stdout)
    }

    // dkms identifier init -a <alias> --witness-url <url> --watcher-url <url>
    pub async fn init_identifier(
        &self,
        witness_urls: &[&str],
        watcher_url: &str,
    ) -> Result<AidInfo> {
        let mut args = vec!["identifier", "init", "-a", &self.alias];
        for w in witness_urls {
            args.extend_from_slice(&["--witness-url", w]);
        }
        args.extend_from_slice(&["--watcher-url", watcher_url]);
        self.run(&args).await?;
        self.get_identifier_info().await
    }

    // dkms identifier info <ALIAS>
    pub async fn get_identifier_info(&self) -> Result<AidInfo> {
        let stdout = self.run(&["identifier", "info", &self.alias]).await?;
        self.parse_aid_info(&stdout)
    }

    fn parse_aid_info(&self, raw: &str) -> Result<AidInfo> {
        let trimmed = raw.trim();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if val.is_object() {
                let aid = val
                    .get("aid")
                    .or_else(|| val.get("prefix"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(trimmed)
                    .to_string();
                let registry_id = val
                    .get("registry_id")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                return Ok(AidInfo { aid, registry_id });
            }
        }
        if trimmed.is_empty() {
            return Err(DauthzError::ParseError(
                "empty response from dkms identifier info".into(),
            ));
        }
        Ok(AidInfo {
            aid: trimmed.to_string(),
            registry_id: None,
        })
    }

    // dkms identifier oobi get -a <alias>
    pub async fn get_oobi(&self) -> Result<Vec<OobiInfo>> {
        let stdout = self
            .run(&["identifier", "oobi", "get", "-a", &self.alias])
            .await?;
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }
        // dkms may return a single object or an array
        if trimmed.starts_with('[') {
            serde_json::from_str(trimmed).map_err(|e| DauthzError::ParseError(e.to_string()))
        } else {
            let oobi: OobiInfo =
                serde_json::from_str(trimmed).map_err(|e| DauthzError::ParseError(e.to_string()))?;
            Ok(vec![oobi])
        }
    }

    // dkms identifier oobi resolve -a <alias> -f <file>
    pub async fn resolve_oobi(&self, file: &Path) -> Result<()> {
        let path = file.to_string_lossy().to_string();
        self.run(&[
            "identifier",
            "oobi",
            "resolve",
            "-a",
            &self.alias,
            "-f",
            &path,
        ])
        .await?;
        Ok(())
    }

    // dkms data sign -a <alias> -m <message>
    pub async fn sign(&self, message: &str) -> Result<String> {
        self.run(&["data", "sign", "-a", &self.alias, "-m", message])
            .await
    }

    // dkms data verify -a <alias> -m <message> -o <oobi>
    pub async fn verify(&self, oobi: &str, message: &str) -> Result<bool> {
        let stdout = self
            .run(&[
                "data",
                "verify",
                "-a",
                &self.alias,
                "-m",
                message,
                "-o",
                oobi,
            ])
            .await?;
        let lower = stdout.to_lowercase();
        Ok(lower.contains("success") || lower.contains("valid") || lower == "true")
    }

    // dkms log kel find -a <alias> -i <identifier> [-o <oobi>]
    pub async fn get_kel(&self, identifier: &str, oobi: Option<&str>) -> Result<String> {
        let mut args = vec!["log", "kel", "find", "-a", &self.alias, "-i", identifier];
        if let Some(o) = oobi {
            args.extend_from_slice(&["-o", o]);
        }
        self.run(&args).await
    }

    // dkms log kel rotate -a <alias> -c <config>
    pub async fn rotate(&self, config_path: &Path) -> Result<()> {
        let path = config_path.to_string_lossy().to_string();
        self.run(&["log", "kel", "rotate", "-a", &self.alias, "-c", &path])
            .await?;
        Ok(())
    }

    // dkms mesagkesto exchange -a <alias> -c <content> -r <receiver>
    pub async fn exchange_message(&self, content: &str, receiver: &str) -> Result<String> {
        self.run(&[
            "mesagkesto",
            "exchange",
            "-a",
            &self.alias,
            "-c",
            content,
            "-r",
            receiver,
        ])
        .await
    }

    // dkms mesagkesto query -a <alias>
    pub async fn query_mailbox(&self) -> Result<String> {
        self.run(&["mesagkesto", "query", "-a", &self.alias]).await
    }

    // dkms identifier export <ALIAS>
    pub async fn export_identifier(&self) -> Result<String> {
        self.run(&["identifier", "export", &self.alias]).await
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }
}
