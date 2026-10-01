use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use dauthz_gate::bridge::cyfron_serviced::CyfronServicedBridge;
use dauthz_gate::bridge::dkms_cli::DkmsCliBridge;
use dauthz_gate::bridge::mock::MockBridge;
use dauthz_gate::bridge::KeriBridge;
use dauthz_gate::ceremony::Gate;
use dauthz_gate::config::{BridgeKind, Config};
use dauthz_gate::identity::ensure_service_identity;
use dauthz_gate::session::{load_or_create_secret, CookieCodec};
use dauthz_gate::store::spawn_reaper;

#[derive(Parser)]
#[command(
    name = "dauthz-gate",
    version,
    about = "auth_request gate: sign in with a Cyfron KERI AID"
)]
struct Cli {
    /// TOML config file; env vars DAUTHZ_<SECTION>__<KEY> override it.
    #[arg(short, long, global = true, env = "DAUTHZ_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the gate (default).
    Serve {
        /// Use an in-process fake KERI bridge (demo only; accepts any
        /// `-MOCK:<aid>` signature).
        #[arg(long, env = "DAUTHZ_MOCK_BRIDGE")]
        mock_bridge: bool,
    },
    /// Load and validate the configuration, then print it.
    CheckConfig,
    /// Print the service identity (alias, AID, OOBI) as JSON, bootstrapping it if needed.
    PrintIdentity,
    /// Print the DAUTHZ_POLICY__* lines for a credential issuer that lives
    /// on a cyfron-serviced you can reach (typically the authority's own).
    PrintIssuerConfig {
        /// Alias of the issuer identity on that daemon.
        #[arg(long)]
        alias: String,
        /// OCA bundle SAID the passports are issued against.
        #[arg(long)]
        schema_said: String,
        #[arg(long, env = "CYFRON_URL")]
        url: Option<String>,
        #[arg(long, env = "CYFRON_TOKEN")]
        token: Option<String>,
        #[arg(long, env = "CYFRON_ENDPOINT_FILE")]
        endpoint_file: Option<PathBuf>,
    },
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

fn real_bridge(cfg: &Config) -> anyhow::Result<Arc<dyn KeriBridge>> {
    let alias = cfg.identity.alias.as_deref().unwrap_or("gate");
    if cfg.bridge.kind == BridgeKind::Dkms {
        let binary = std::env::var_os("DKMS_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| cfg.dkms.binary.clone());
        if cfg.requires_credential() {
            tracing::warn!(
                "the dkms bridge checks only the issuer signature of a credential: \
                 no registry or expiry check (revocation_check=required refuses all)"
            );
        }
        return Ok(Arc::new(DkmsCliBridge::new(
            binary,
            cfg.dkms.home.clone(),
            Duration::from_secs(cfg.dkms.timeout_secs),
            alias,
        )));
    }
    Ok(Arc::new(CyfronServicedBridge::from_config(
        cfg.cyfron.url.as_deref(),
        cfg.cyfron.token.as_deref(),
        cfg.cyfron.endpoint_file.as_deref(),
        Duration::from_secs(cfg.cyfron.timeout_secs),
        alias,
    )?))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve { mock_bridge: false }) {
        Command::CheckConfig => {
            let cfg = Config::load(cli.config.as_deref())?;
            println!("{}", toml::to_string_pretty(&cfg)?);
        }
        Command::PrintIdentity => {
            let cfg = Config::load(cli.config.as_deref())?;
            let bridge = real_bridge(&cfg)?;
            let id = ensure_service_identity(&cfg, bridge.as_ref()).await?;
            println!("{}", serde_json::to_string_pretty(&id)?);
        }
        Command::PrintIssuerConfig {
            alias,
            schema_said,
            url,
            token,
            endpoint_file,
        } => {
            let bridge = CyfronServicedBridge::from_config(
                url.as_deref(),
                token.as_deref(),
                endpoint_file.as_deref(),
                Duration::from_secs(30),
                &alias,
            )?;
            let info = bridge.identifier_by_alias(&alias).await?.ok_or_else(|| {
                anyhow::anyhow!("no identifier with alias '{alias}' on that daemon")
            })?;
            println!("DAUTHZ_POLICY__MODE=credential");
            println!("DAUTHZ_POLICY__SCHEMA_SAID={schema_said}");
            println!("DAUTHZ_POLICY__ISSUER_AID={}", info.aid);
            println!(
                "DAUTHZ_POLICY__ISSUER_OOBI='{}'",
                serde_json::to_string(&info.oobi)?
            );
        }
        Command::Serve { mock_bridge } => serve(cli.config.as_deref(), mock_bridge).await?,
    }
    Ok(())
}

async fn serve(config: Option<&std::path::Path>, mock_bridge: bool) -> anyhow::Result<()> {
    let cfg = Config::load(config)?;
    let secret = load_or_create_secret(cfg.cookie.secret.as_deref(), &cfg.cookie_secret_path())?;
    let bridge: Arc<dyn KeriBridge> = if mock_bridge {
        tracing::warn!("running with the MOCK bridge: signatures are NOT verified");
        Arc::new(MockBridge::new())
    } else {
        real_bridge(&cfg)?
    };
    let gate = Arc::new(Gate::new(cfg.clone(), bridge, CookieCodec::new(secret)));
    spawn_reaper(
        gate.challenges.clone(),
        gate.pending.clone(),
        Duration::from_secs(60),
    );

    // Bootstrap the service identity in the background so /healthz answers
    // (503) while the daemon is still creating the identity.
    {
        let gate = gate.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(2);
            loop {
                match ensure_service_identity(&gate.config, gate.bridge.as_ref()).await {
                    Ok(id) => {
                        tracing::info!(alias = %id.alias, aid = %id.aid, "service identity ready");
                        gate.set_identity(id).await;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("service identity not ready: {e}; retrying in {delay:?}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(30));
                    }
                }
            }
            if gate.config.requires_credential() {
                let every = Duration::from_secs(gate.config.policy.issuer_refresh_secs.max(30));
                loop {
                    gate.refresh_issuer_kel().await;
                    tokio::time::sleep(every).await;
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.http.listen).await?;
    tracing::info!(
        listen = %cfg.http.listen,
        prefix = %cfg.site.path_prefix,
        callback = %cfg.callback_url(),
        mode = ?cfg.policy.mode,
        "dauthz-gate serving"
    );
    axum::serve(listener, dauthz_gate::http::router(gate)).await?;
    Ok(())
}
