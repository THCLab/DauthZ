//! Gate configuration: a TOML file layered with `DAUTHZ_<SECTION>__<KEY>`
//! environment variables. Everything has a default except what genuinely
//! identifies a deployment (site origin, daemon endpoint, policy).

use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub site: SiteConfig,
    pub http: HttpConfig,
    pub cookie: CookieConfig,
    pub cyfron: CyfronConfig,
    pub identity: IdentityConfig,
    pub policy: PolicyConfig,
    pub ui: UiConfig,
    /// Persistent state: service identity, cookie secret.
    pub data_dir: PathBuf,
    /// How long a minted challenge (and its pending session) stays valid.
    pub challenge_ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            site: SiteConfig::default(),
            http: HttpConfig::default(),
            cookie: CookieConfig::default(),
            cyfron: CyfronConfig::default(),
            identity: IdentityConfig::default(),
            policy: PolicyConfig::default(),
            ui: UiConfig::default(),
            data_dir: PathBuf::from("/data"),
            challenge_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteConfig {
    /// Public origin browsers and wallets use, e.g. `https://docs.example.org`.
    /// The callback URL and the deep link's `sp_origin` derive from it.
    pub origin: String,
    pub name: String,
    pub logo_url: Option<String>,
    /// URL prefix under which nginx proxies the gate. Every route lives
    /// below it, including the `auth_request` target.
    pub path_prefix: String,
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            origin: String::new(),
            name: "Protected site".into(),
            logo_url: None,
            path_prefix: "/dauthz".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub listen: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8088".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CookieConfig {
    pub name: String,
    /// Base64 or raw secret; when unset one is generated and persisted at
    /// `secret_file` (relative paths resolve under `data_dir`).
    pub secret: Option<String>,
    pub secret_file: PathBuf,
    pub ttl_secs: u64,
    pub secure: bool,
    pub domain: Option<String>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "dauthz_session".into(),
            secret: None,
            secret_file: PathBuf::from("cookie-secret"),
            ttl_secs: 12 * 3600,
            secure: true,
            domain: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CyfronConfig {
    /// Base URL of the SP-side `cyfron-serviced`, e.g. `http://cyfron-serviced:51234`.
    pub url: Option<String>,
    /// Bearer token; wins over `endpoint_file`.
    pub token: Option<String>,
    /// The daemon's `endpoint.json` (`{url, token}`), re-read on a 401.
    pub endpoint_file: Option<PathBuf>,
    pub deep_link_scheme: String,
    pub timeout_secs: u64,
}

impl Default for CyfronConfig {
    fn default() -> Self {
        Self {
            url: None,
            token: None,
            endpoint_file: None,
            deep_link_scheme: "cyfron".into(),
            timeout_secs: 90,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Human name of the service identity created on the daemon.
    pub name: Option<String>,
    /// Alias of an existing identity on the daemon (skips discovery).
    pub alias: Option<String>,
    /// Pin an AID + OOBI without touching the daemon's identifier list.
    pub aid: Option<String>,
    pub oobi: Option<String>,
    /// LocationScheme JSON strings, as `POST /identifiers` expects.
    #[serde(deserialize_with = "string_or_list")]
    pub witness_locations: Vec<String>,
    pub watcher_location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Only AIDs listed in `allowed_aids` may enter.
    Allowlist,
    /// Any AID that presents a valid credential matching the policy.
    Credential,
    /// Any AID with a valid signature. Must be chosen explicitly.
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationCheck {
    /// Ignore the daemon's revocation row entirely.
    Off,
    /// Deny only when the registry positively reports `revoked`.
    IfKnown,
    /// Require a positive `issued` answer from the registry.
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presentation {
    /// Credential arrives in the wallet callback (needs a wallet with
    /// `requested_credentials` support).
    Inline,
    /// Credential is pasted on the `/present` page after AID sign-in.
    Page,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub mode: PolicyMode,
    #[serde(deserialize_with = "string_or_list")]
    pub allowed_aids: Vec<String>,
    /// OCA bundle SAID the credential's `s` must equal.
    pub schema_said: Option<String>,
    /// Issuer AID the credential's `i` must equal.
    pub issuer_aid: Option<String>,
    /// The issuer's OOBI (JSON), resolved on the daemon so its KEL is known.
    pub issuer_oobi: Option<String>,
    pub revocation_check: RevocationCheck,
    pub issuer_refresh_secs: u64,
    pub presentation: Presentation,
    /// Text shown on the login page describing what is required.
    pub requirement_text: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Allowlist,
            allowed_aids: Vec::new(),
            schema_said: None,
            issuer_aid: None,
            issuer_oobi: None,
            revocation_check: RevocationCheck::IfKnown,
            issuer_refresh_secs: 600,
            presentation: Presentation::Both,
            requirement_text: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    /// Raw HTML injected into the login page head (`{{THEME_HEAD}}`).
    pub theme_head: String,
    pub build_version: Option<String>,
}

/// Accept `["a","b"]`, `"a,b"` or `""` — env vars can only carry strings.
/// A string that is itself JSON (`[…]` array or a single `{…}` object) is
/// taken as such rather than split on commas, so LocationScheme entries
/// like `{"eid":…,"scheme":"http","url":…}` survive.
fn string_or_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        List(Vec<String>),
        Text(String),
    }
    Ok(match Raw::deserialize(d)? {
        Raw::List(v) => v,
        Raw::Text(s) => parse_list_text(&s),
    })
}

fn parse_list_text(s: &str) -> Vec<String> {
    let t = s.trim();
    if t.starts_with('[') {
        if let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(t) {
            return values
                .into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                })
                .collect();
        }
    }
    if t.starts_with('{') {
        return vec![t.to_string()];
    }
    t.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Config {
    /// Layer defaults, an optional TOML file and `DAUTHZ_*` env vars
    /// (`DAUTHZ_SITE__ORIGIN`, `DAUTHZ_POLICY__ALLOWED_AIDS`, …).
    pub fn load(file: Option<&Path>) -> anyhow::Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(path) = file {
            fig = fig.merge(Toml::file(path));
        }
        fig = fig.merge(Env::prefixed("DAUTHZ_").split("__"));
        let cfg: Config = fig.extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let origin = self.site.origin.trim_end_matches('/');
        if origin.is_empty() {
            anyhow::bail!("site.origin is required (DAUTHZ_SITE__ORIGIN)");
        }
        url::Url::parse(origin).map_err(|e| anyhow::anyhow!("site.origin is not a URL: {e}"))?;
        if !self.site.path_prefix.starts_with('/') || self.site.path_prefix.ends_with('/') {
            anyhow::bail!("site.path_prefix must start with '/' and not end with one");
        }
        if self.cyfron.url.is_none() && self.cyfron.endpoint_file.is_none() {
            anyhow::bail!("cyfron.url (with cyfron.token) or cyfron.endpoint_file is required");
        }
        if self.identity.aid.is_some() != self.identity.oobi.is_some() {
            anyhow::bail!("identity.aid and identity.oobi must be set together");
        }
        match self.policy.mode {
            PolicyMode::Allowlist if self.policy.allowed_aids.is_empty() => {
                anyhow::bail!("policy.mode=allowlist needs at least one policy.allowed_aids entry")
            }
            PolicyMode::Credential => {
                for (k, v) in [
                    ("schema_said", &self.policy.schema_said),
                    ("issuer_aid", &self.policy.issuer_aid),
                    ("issuer_oobi", &self.policy.issuer_oobi),
                ] {
                    if v.as_deref().map(str::trim).unwrap_or("").is_empty() {
                        anyhow::bail!("policy.mode=credential needs policy.{k}");
                    }
                }
                if let Some(o) = &self.policy.issuer_oobi {
                    serde_json::from_str::<serde_json::Value>(o)
                        .map_err(|e| anyhow::anyhow!("policy.issuer_oobi is not JSON: {e}"))?;
                }
            }
            _ => {}
        }
        if self.cookie.ttl_secs == 0 || self.challenge_ttl_secs == 0 {
            anyhow::bail!("cookie.ttl_secs and challenge_ttl_secs must be > 0");
        }
        Ok(())
    }

    pub fn origin(&self) -> String {
        self.site.origin.trim_end_matches('/').to_string()
    }

    pub fn prefixed(&self, path: &str) -> String {
        format!("{}{}", self.site.path_prefix, path)
    }

    pub fn callback_url(&self) -> String {
        format!("{}{}", self.origin(), self.prefixed("/connect/callback"))
    }

    pub fn cookie_secret_path(&self) -> PathBuf {
        if self.cookie.secret_file.is_absolute() {
            self.cookie.secret_file.clone()
        } else {
            self.data_dir.join(&self.cookie.secret_file)
        }
    }

    pub fn requires_credential(&self) -> bool {
        self.policy.mode == PolicyMode::Credential
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        let mut c = Config::default();
        c.site.origin = "https://docs.example.org/".into();
        c.cyfron.url = Some("http://cyfron:51234".into());
        c.cyfron.token = Some("t".into());
        c.policy.allowed_aids = vec!["EA".into()];
        c
    }

    #[test]
    fn defaults_validate_with_the_minimum_fields() {
        let c = base();
        c.validate().unwrap();
        assert_eq!(
            c.callback_url(),
            "https://docs.example.org/dauthz/connect/callback"
        );
    }

    #[test]
    fn allowlist_needs_entries_and_credential_needs_the_triple() {
        let mut c = base();
        c.policy.allowed_aids.clear();
        assert!(c.validate().is_err());
        c.policy.mode = PolicyMode::Credential;
        assert!(c.validate().is_err());
        c.policy.schema_said = Some("ES".into());
        c.policy.issuer_aid = Some("EI".into());
        c.policy.issuer_oobi = Some("[]".into());
        c.validate().unwrap();
        c.policy.issuer_oobi = Some("not json".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn lists_keep_json_entries_intact() {
        let one = r#"{"eid":"B1","scheme":"http","url":"http://w/"}"#;
        assert_eq!(parse_list_text(one), vec![one]);
        let arr = format!("[{one},{}]", r#"{"eid":"B2","scheme":"http","url":"http://x/"}"#);
        let parsed = parse_list_text(&arr);
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("\"eid\":\"B1\""));
        assert_eq!(parse_list_text(r#"["a","b"]"#), vec!["a", "b"]);
    }

    #[test]
    fn lists_accept_comma_separated_strings() {
        let v: PolicyConfig = serde_json::from_str(r#"{"allowed_aids":"EA, EB,,"}"#).unwrap();
        assert_eq!(v.allowed_aids, vec!["EA", "EB"]);
        let v: PolicyConfig = serde_json::from_str(r#"{"allowed_aids":["EA"]}"#).unwrap();
        assert_eq!(v.allowed_aids, vec!["EA"]);
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn env_overrides_layer_over_defaults() {
        figment::Jail::expect_with(|j| {
            j.set_env("DAUTHZ_SITE__ORIGIN", "http://localhost:8080");
            j.set_env("DAUTHZ_CYFRON__URL", "http://c:1");
            j.set_env("DAUTHZ_CYFRON__TOKEN", "x");
            j.set_env("DAUTHZ_POLICY__MODE", "open");
            j.set_env("DAUTHZ_COOKIE__SECURE", "false");
            let c = Config::load(None).unwrap();
            assert_eq!(c.policy.mode, PolicyMode::Open);
            assert!(!c.cookie.secure);
            assert_eq!(c.origin(), "http://localhost:8080");
            Ok(())
        });
    }
}
