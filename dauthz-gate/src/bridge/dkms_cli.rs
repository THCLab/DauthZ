//! [`KeriBridge`] over the `dkms` CLI (dkms-bin), for deployments with no
//! `cyfron-serviced` daemon. Every call is a subprocess; the gate still
//! holds no keys and links no KERI crate.
//!
//! dkms keeps one database per alias that admits a single opener, so calls
//! are serialized. Verification is `dkms auth verify`, which reports the
//! daemon's `{valid, authorized, signer_aid}` verdict but authorizes only
//! the main AID itself: delegated devices and multisig members are refused.
//! Credential checks cover the issuer signature only (see
//! [`DkmsCliBridge::verify_credential`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use super::*;

pub struct DkmsCliBridge {
    binary: PathBuf,
    /// `HOME` for the subprocess: dkms keeps its state in `$HOME/.dkms-dev-cli`.
    home: Option<PathBuf>,
    timeout: Duration,
    alias: Mutex<String>,
    /// OOBIs passed to `resolve_oobi`, by the AID they name, so a later
    /// verification can hand dkms the signer's OOBI as well.
    oobis: Mutex<HashMap<String, String>>,
    serial: tokio::sync::Mutex<()>,
}

/// What a finished dkms run printed.
struct Output {
    stdout: String,
}

impl DkmsCliBridge {
    pub fn new(binary: PathBuf, home: Option<PathBuf>, timeout: Duration, alias: &str) -> Self {
        Self {
            binary,
            home,
            timeout,
            alias: Mutex::new(alias.to_string()),
            oobis: Mutex::new(HashMap::new()),
            serial: tokio::sync::Mutex::new(()),
        }
    }

    /// Run dkms and return its stdout. dkms reports failures on stdout with
    /// exit code 1 (and panics with 101), so a non-zero exit carries both
    /// streams back as the error body.
    async fn run(&self, args: &[&str]) -> Result<Output, BridgeError> {
        let _turn = self.serial.lock().await;
        let mut cmd = Command::new(&self.binary);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(home) = &self.home {
            cmd.env("HOME", home);
        }
        let child = cmd.spawn().map_err(|e| {
            BridgeError::Transport(format!("cannot run {}: {e}", self.binary.display()))
        })?;
        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                BridgeError::Transport(format!(
                    "dkms {} timed out after {:?}",
                    args.first().copied().unwrap_or_default(),
                    self.timeout
                ))
            })?
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(BridgeError::Status {
                status: out.status.code().map(|c| c as u16).unwrap_or(0),
                body: format!("{} {}", stdout.trim(), stderr.trim())
                    .trim()
                    .to_string(),
            });
        }
        Ok(Output { stdout })
    }

    async fn run_json<T: serde::de::DeserializeOwned>(
        &self,
        args: &[&str],
    ) -> Result<T, BridgeError> {
        let out = self.run(args).await?;
        serde_json::from_str(out.stdout.trim()).map_err(|e| {
            BridgeError::Parse(format!(
                "dkms {}: {e}: {}",
                args.join(" "),
                out.stdout.trim()
            ))
        })
    }

    async fn oobi_of(&self, alias: &str) -> Result<serde_json::Value, BridgeError> {
        self.run_json(&["identifier", "oobi", "get", "-a", alias])
            .await
    }

    /// `auth verify` for `main_aid`, passing the signer's OOBI when one was
    /// resolved earlier.
    async fn verify(&self, main_aid: &str, cesr: &str) -> Result<IntroductionVerdict, BridgeError> {
        let alias = self.alias();
        let oobi = self.oobis.lock().unwrap().get(main_aid).cloned();
        let mut args = vec!["auth", "verify", "-a", &alias, "--aid", main_aid];
        if let Some(o) = &oobi {
            args.extend(["--oobi", o.as_str()]);
        }
        args.extend(["-m", cesr]);
        let out = self.run(&args).await?;
        Ok(parse_introduction_response(out.stdout.trim()))
    }
}

/// The `url` of a LocationScheme JSON string, which is what
/// `dkms identifier init --witness-url` takes.
fn location_url(location: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(location).ok()?;
    v.get("url")?.as_str().map(str::to_string)
}

#[derive(serde::Deserialize)]
struct Listed {
    alias: String,
    aid: String,
}

#[async_trait]
impl KeriBridge for DkmsCliBridge {
    fn alias(&self) -> String {
        self.alias.lock().unwrap().clone()
    }

    fn set_alias(&self, alias: &str) {
        *self.alias.lock().unwrap() = alias.into();
    }

    async fn identifier_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentifierInfo>, BridgeError> {
        let Some(found) = self
            .list_identifiers()
            .await?
            .into_iter()
            .find(|i| i.alias == alias)
        else {
            return Ok(None);
        };
        Ok(Some(IdentifierInfo {
            oobi: self.oobi_of(alias).await?,
            ..found
        }))
    }

    async fn list_identifiers(&self) -> Result<Vec<IdentifierInfo>, BridgeError> {
        let listed: Vec<Listed> = self.run_json(&["identifier", "list", "--json"]).await?;
        Ok(listed
            .into_iter()
            .map(|l| IdentifierInfo {
                name: l.alias.clone(),
                alias: l.alias,
                aid: l.aid,
                oobi: serde_json::Value::Null,
            })
            .collect())
    }

    async fn create_identifier(
        &self,
        req: &CreateIdentifier,
    ) -> Result<IdentifierInfo, BridgeError> {
        let alias = format!(
            "{}-{}",
            crate::identity::slug(&req.name),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let mut args = vec![
            "identifier".to_string(),
            "init".into(),
            "-a".into(),
            alias.clone(),
        ];
        for w in &req.witness_urls {
            let url = location_url(w)
                .ok_or_else(|| BridgeError::Config(format!("witness location has no url: {w}")))?;
            args.extend(["--witness-url".into(), url]);
        }
        if let Some(w) = &req.watcher_url {
            let url = location_url(w)
                .ok_or_else(|| BridgeError::Config(format!("watcher location has no url: {w}")))?;
            args.extend(["--watcher-url".into(), url]);
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&refs).await?;
        self.identifier_by_alias(&alias)
            .await?
            .ok_or_else(|| BridgeError::Parse(format!("dkms created no identifier '{alias}'")))
    }

    async fn resolve_oobi(&self, oobi: &serde_json::Value) -> Result<ResolveOutcome, BridgeError> {
        // dkms reads a JSON array of OOBIs from a file.
        let list = match oobi {
            serde_json::Value::Array(_) => oobi.clone(),
            other => serde_json::Value::Array(vec![other.clone()]),
        };
        let text = list.to_string();
        let file = tempfile::Builder::new()
            .prefix("dauthz-oobi-")
            .suffix(".json")
            .tempfile()
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        std::fs::write(file.path(), &text).map_err(|e| BridgeError::Transport(e.to_string()))?;
        let path = file.path().to_string_lossy().into_owned();
        let alias = self.alias();
        self.run(&["identifier", "oobi", "resolve", "-a", &alias, "-f", &path])
            .await?;
        if let Some(aid) = dauthz_core::sp_auth::extract_aid_from_oobi(&text) {
            self.oobis.lock().unwrap().insert(aid, text);
        }
        Ok(ResolveOutcome {
            resolved: list.as_array().map(Vec::len).unwrap_or(0),
            ..Default::default()
        })
    }

    async fn verify_introduction(
        &self,
        main_aid: &str,
        cesr: &str,
    ) -> Result<IntroductionVerdict, BridgeError> {
        self.verify(main_aid, cesr).await
    }

    async fn sign(&self, payload: &str) -> Result<String, BridgeError> {
        let alias = self.alias();
        let out = self
            .run(&["data", "sign", "-a", &alias, "-m", payload])
            .await?;
        Ok(out.stdout.trim().to_string())
    }

    /// dkms can check the issuer's signature over the ACDC but has no
    /// registry or expiry check to match the daemon's report. The rows are
    /// filled accordingly: `signature` and `binding` follow the issuer
    /// signature, `validity` passes (no expiry is read), and `revocation`
    /// stays `unknown`, so `revocation_check = "required"` refuses every
    /// credential while `if_known` and `off` admit them.
    async fn verify_credential(
        &self,
        acdc: &str,
        issuer_cesr: &str,
    ) -> Result<CredentialVerification, BridgeError> {
        let row = |id: &str, state: CheckState, detail: &str| CredentialCheck {
            id: id.into(),
            state,
            detail: detail.into(),
        };
        let value: serde_json::Value = serde_json::from_str(acdc)
            .map_err(|e| BridgeError::Parse(format!("credential is not JSON: {e}")))?;
        let field = |k: &str| value.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let Some(issuer) = field("i") else {
            return Ok(CredentialVerification {
                checks: vec![row(
                    "binding",
                    CheckState::Fail,
                    "credential names no issuer",
                )],
                ..Default::default()
            });
        };
        let verdict = self
            .verify(&issuer, &format!("{acdc}{issuer_cesr}"))
            .await?;
        let signed = if verdict.accepted() {
            CheckState::Pass
        } else {
            CheckState::Fail
        };
        let attributes = value
            .get("a")
            .and_then(|a| a.as_object())
            .map(|a| {
                a.iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "d" | "i" | "u"))
                    .map(|(k, v)| CredentialAttribute {
                        name: k.clone(),
                        label: None,
                        value: v.clone(),
                        sensitive: false,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(CredentialVerification {
            ok: signed == CheckState::Pass,
            checks: vec![
                row("signature", signed, "issuer signature checked by dkms"),
                row("binding", signed, "covered by the issuer signature"),
                row(
                    "validity",
                    CheckState::Pass,
                    "expiry not checked by the dkms bridge",
                ),
                row(
                    "revocation",
                    CheckState::Unknown,
                    "registry not queried by the dkms bridge",
                ),
            ],
            said: field("d"),
            issuer_aid: Some(issuer),
            schema_said: field("s"),
            issued_at: value
                .get("a")
                .and_then(|a| a.get("dt"))
                .and_then(|d| d.as_str())
                .map(str::to_string),
            expires_at: None,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in `dkms` that answers from a canned script and logs its
    /// arguments, so the bridge's command lines and parsing are tested
    /// without KERI infrastructure.
    fn fake_dkms(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("dkms");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$@\" >> \"{}/calls.log\"\n{body}\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn calls(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    fn bridge(bin: PathBuf) -> DkmsCliBridge {
        DkmsCliBridge::new(bin, None, Duration::from_secs(10), "svc")
    }

    #[tokio::test]
    async fn identifiers_come_from_list_and_oobi_get() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_dkms(
            dir.path(),
            r#"case "$1 $2" in
  "identifier list") echo '[{"alias":"svc","aid":"ESVC"}]' ;;
  "identifier oobi") echo '[{"cid":"ESVC","role":"witness","eid":"BW"}]' ;;
esac"#,
        );
        let b = bridge(bin);
        let info = b.identifier_by_alias("svc").await.unwrap().unwrap();
        assert_eq!(info.aid, "ESVC");
        assert_eq!(info.oobi[0]["cid"], "ESVC");
        assert!(b.identifier_by_alias("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn verification_passes_the_resolved_oobi_and_reads_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_dkms(
            dir.path(),
            r#"case "$1 $2" in
  "auth verify") echo '{"valid":true,"authorized":true,"signer_aid":"EUSER"}' ;;
esac"#,
        );
        let b = bridge(bin);
        let oobi = serde_json::json!({"cid":"EUSER","role":"witness","eid":"BW"});
        assert_eq!(b.resolve_oobi(&oobi).await.unwrap().resolved, 1);
        let v = b.verify_introduction("EUSER", "{}-AAB").await.unwrap();
        assert!(v.accepted());
        assert_eq!(v.signer_aid.as_deref(), Some("EUSER"));
        let log = calls(dir.path());
        assert!(log.contains("identifier oobi resolve -a svc -f "), "{log}");
        assert!(
            log.contains(r#"auth verify -a svc --aid EUSER --oobi [{"cid":"EUSER","eid":"BW","role":"witness"}] -m {}-AAB"#),
            "{log}"
        );
    }

    #[tokio::test]
    async fn failures_map_to_bridge_errors_and_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_dkms(
            dir.path(),
            r#"case "$1 $2" in
  "auth verify") echo '{"valid":true,"authorized":false,"signer_aid":"EOTHER"}' ;;
  "data sign") echo "Unknown identifier: svc"; exit 1 ;;
  "identifier list") echo 'not json' ;;
esac"#,
        );
        let b = bridge(bin);
        assert!(!b
            .verify_introduction("EUSER", "x")
            .await
            .unwrap()
            .accepted());
        match b.sign("{}").await {
            Err(BridgeError::Status { status: 1, body }) => {
                assert!(body.contains("Unknown identifier"))
            }
            other => panic!("expected a status error, got {other:?}"),
        }
        assert!(matches!(
            b.list_identifiers().await,
            Err(BridgeError::Parse(_))
        ));
        let missing = bridge(dir.path().join("no-such-dkms"));
        assert!(matches!(
            missing.list_identifiers().await,
            Err(BridgeError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn create_passes_witness_and_watcher_urls() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_dkms(
            dir.path(),
            r#"case "$1 $2" in
  "identifier init") mkdir -p "$(dirname "$0")/made"; echo "$4" > "$(dirname "$0")/made/alias" ;;
  "identifier list") a=$(cat "$(dirname "$0")/made/alias" 2>/dev/null); echo "[{\"alias\":\"$a\",\"aid\":\"ENEW\"}]" ;;
  "identifier oobi") echo '[]' ;;
esac"#,
        );
        let b = bridge(bin);
        let info = b
            .create_identifier(&CreateIdentifier {
                name: "Demo Gate".into(),
                description: String::new(),
                witness_urls: vec![r#"{"eid":"BW","scheme":"http","url":"http://w:3232/"}"#.into()],
                watcher_url: Some(r#"{"eid":"BX","scheme":"http","url":"http://x:3235/"}"#.into()),
            })
            .await
            .unwrap();
        assert!(info.alias.starts_with("demo-gate-"));
        assert_eq!(info.aid, "ENEW");
        let log = calls(dir.path());
        assert!(
            log.contains("--witness-url http://w:3232/ --watcher-url http://x:3235/"),
            "{log}"
        );
    }

    #[tokio::test]
    async fn credential_rows_follow_the_issuer_signature() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_dkms(
            dir.path(),
            r#"echo '{"valid":true,"authorized":true,"signer_aid":"EISS"}'"#,
        );
        let b = bridge(bin);
        let acdc =
            r#"{"v":"ACDC10JSON","d":"ECRED","i":"EISS","s":"ESCH","a":{"i":"EHOLD","role":"r"}}"#;
        let report = b.verify_credential(acdc, "-AABsig").await.unwrap();
        assert_eq!(report.said.as_deref(), Some("ECRED"));
        assert_eq!(report.state_of("signature"), CheckState::Pass);
        assert_eq!(report.state_of("binding"), CheckState::Pass);
        assert_eq!(report.state_of("revocation"), CheckState::Unknown);
        assert_eq!(report.attributes.len(), 1);
        assert!(calls(dir.path()).contains("auth verify -a svc --aid EISS"));
    }
}
