//! The goethite binary: command-line interface, configuration and wiring.

mod cluster;
mod config;
mod control;
mod download;
mod filters;
mod handoff;
mod lists;
mod metrics;
mod node;
mod notify;
mod observe;
mod plane;
mod privileges;
mod secrets;
mod sockets;
mod vrrp;

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use clap::{Parser, Subcommand};
use goethite_api::{Api, ApiConfig, EmbeddedDocs, EmbeddedWeb, WebAssets};
use goethite_resolver::{
    Cache, Forwarder, ForwarderConfig, Policy, PolicyState, Resolver, health_record, test_record,
};
use goethite_server::Server;
use goethite_store::{Actor, Import, Store};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::config::Config;
use crate::control::Control;
use crate::lists::ListStore;
use crate::secrets::Secrets;
use crate::sockets::Sockets;

/// The `meta` key holding a fingerprint of the last imported `[filter]`.
const IMPORTED_FILTER: &str = "imported_filter";

/// A self-hosted, clustered, security-hardened DNS filtering resolver.
#[derive(Debug, Parser)]
#[command(name = "goethite", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the DNS server until SIGINT or SIGTERM.
    Run {
        /// Path to the TOML configuration file.
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
    },
    /// Check a configuration file and its filter lists without starting the
    /// server. Exits with status 1 if anything is wrong.
    CheckConfig {
        /// Path to the TOML configuration file.
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
    },
    /// Import the `[filter]` table of the config file into the store,
    /// replacing the lists and rules imported before. goethite must not be
    /// running.
    Import {
        /// Path to the TOML configuration file.
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
    },
    /// Generate an admin token for the API and print it with the hash that
    /// goes into the config file.
    Token,
    /// Print the API's OpenAPI document.
    Openapi,
    /// Create the certificates a cluster's nodes use to recognize each
    /// other.
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
    },
    /// Hold the floating IP of the `[vrrp]` table while this node should:
    /// run beside `goethite run`, with `CAP_NET_ADMIN` and `CAP_NET_RAW`
    /// (Linux), until SIGINT or SIGTERM.
    Vrrp {
        /// Path to the TOML configuration file.
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
    },
    /// Open the terminal UI for a goethite node, through its API.
    Tui {
        /// The API's address. Defaults to `GOETHITE_API`, then
        /// `http://127.0.0.1:8053`.
        #[arg(long, value_name = "URL")]
        api: Option<String>,
        /// A file holding the admin token. Without it, the `GOETHITE_TOKEN`
        /// environment variable is used, if set.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
        /// A PEM CA certificate, for a node that serves HTTPS with its own.
        #[arg(long, value_name = "PATH")]
        ca_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ClusterCommand {
    /// Create the cluster's CA: `ca.crt` and `ca.key` in DIR.
    Init {
        /// Where to put them.
        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: PathBuf,
    },
    /// Create a certificate for NODE, signed by the CA in DIR: `NODE.crt`
    /// and `NODE.key`.
    Cert {
        /// The node's name, as in its `[cluster]` table.
        node: String,
        /// Where the CA is, and where to put the certificate.
        #[arg(long, value_name = "DIR", default_value = ".")]
        dir: PathBuf,
        /// Replace an existing certificate for NODE.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Log lines would garble the terminal UI.
    let tui_mode = matches!(cli.command, Command::Tui { .. });
    if !tui_mode {
        init_logging();
    }
    let result = match cli.command {
        Command::Run { config } => run(&config),
        Command::CheckConfig { config } => check_config(&config),
        Command::Import { config } => import(&config),
        Command::Vrrp { config } => vrrp::run(&config),
        Command::Token => token(),
        Command::Openapi => print(&goethite_api::openapi_json()),
        Command::Cluster { command } => match command {
            ClusterCommand::Init { dir } => cluster::init(&dir).and_then(|text| print(&text)),
            ClusterCommand::Cert { node, dir, force } => {
                cluster::cert(&dir, &node, force).and_then(|text| print(&text))
            }
        },
        Command::Tui {
            api,
            token_file,
            ca_file,
        } => tui(api, token_file.as_deref(), ca_file.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if tui_mode {
                // The terminal is restored by now.
                init_logging();
            }
            error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Logs to stderr. `RUST_LOG` overrides the default level (`info`).
///
/// hickory-proto logs its own warnings about malformed wire data, quoting
/// attacker-controlled bytes at a much larger size than the packet. goethite
/// reports rejected messages itself, so hickory stays silent unless `RUST_LOG`
/// names it explicitly.
fn init_logging() {
    let directives = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default();
    let mut filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(&directives);
    if !directives.contains("hickory")
        && let Ok(quiet) = "hickory_proto=off".parse()
    {
        filter = filter.add_directive(quiet);
    }
    // Only fails if a global subscriber is already set, which never happens here.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        // Otherwise a log line that cannot be written (nothing reads standard
        // error any more) is reported with `eprintln!`, which panics: the
        // process dies, or the task that logged does, such as the one that
        // stops goethite on SIGTERM. A lost log line must cost nothing more.
        .log_internal_errors(false)
        .try_init();
}

fn run(config_path: &Path) -> Result<()> {
    // First, before any file is opened: sockets systemd kept for goethite
    // across a restart.
    let from_systemd = sockets::take_systemd_fds();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "starting goethite"
    );
    let config_path = std::path::absolute(config_path)
        .with_context(|| format!("cannot resolve {}", config_path.display()))?;
    // Remembered now: an upgrade starts whatever binary is at this path
    // then, while this process's own file may be gone by then.
    let binary = std::env::current_exe().context("cannot find goethite's own binary")?;
    let config = Config::load(&config_path)?;
    let child = handoff::Child::from_env()?;
    let result = start(&config, &config_path, &binary, from_systemd, child.as_ref());
    if let (Err(err), Some(child)) = (&result, &child) {
        child.failed(&format!("{err:#}"));
    }
    result
}

/// Takes the sockets (from the goethite this one takes over from, from
/// systemd, or by binding) and the keys while the process may still be
/// privileged and has no threads, drops privileges, and serves.
fn start(
    config: &Config,
    config_path: &Path,
    binary: &Path,
    from_systemd: Vec<(String, std::os::fd::OwnedFd)>,
    child: Option<&handoff::Child>,
) -> Result<()> {
    let account = config
        .server
        .user
        .as_deref()
        .map(privileges::lookup)
        .transpose()?;
    let (sockets, secrets) = match child {
        Some(child) => {
            let (named, handed_over) = child.receive()?;
            let sockets = Sockets::adopt(config, named)?;
            info!("took over the previous goethite's sockets");
            (sockets, Secrets::read_or(config, handed_over))
        }
        None => (sockets_from(config, from_systemd)?, Secrets::read(config)?),
    };
    privileges::drop_privileges(account.as_ref())?;
    if let Some(child) = child {
        // Waits for the previous goethite to close the store.
        child.adopted()?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(serve(config, config_path, binary, sockets, &secrets, child))
}

/// The sockets systemd kept, if they still fit the config file; otherwise
/// freshly bound ones.
fn sockets_from(
    config: &Config,
    from_systemd: Vec<(String, std::os::fd::OwnedFd)>,
) -> Result<Sockets> {
    if from_systemd.is_empty() {
        return Sockets::bind(config);
    }
    let names: Vec<String> = from_systemd.iter().map(|(name, _)| name.clone()).collect();
    match Sockets::adopt(config, from_systemd) {
        Ok(sockets) => {
            info!(sockets = names.len(), "took over the sockets systemd kept");
            Ok(sockets)
        }
        Err(err) => {
            warn!("{err:#}; binding them afresh");
            for name in &names {
                notify::forget(name);
            }
            // systemd lets go of its copies in a moment.
            for _ in 0..20 {
                match Sockets::bind(config) {
                    Ok(sockets) => return Ok(sockets),
                    Err(err) => {
                        tracing::debug!("{err:#}; trying again");
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
            Sockets::bind(config)
        }
    }
}

/// The resolver for `config`, steered by `state`.
fn resolver(config: &Config, state: &Arc<PolicyState>) -> Result<Resolver> {
    let upstreams: Vec<_> = config
        .upstream
        .iter()
        .map(config::UpstreamSection::to_upstream)
        .collect();
    for upstream in &upstreams {
        info!(address = %upstream.address, transport = ?upstream.transport, "upstream");
    }
    let forwarder = Forwarder::new(ForwarderConfig::new(upstreams))
        .context("invalid [[upstream]] configuration")?;
    let cache = Cache::new(config.cache.to_cache_config());
    info!(max_entries = config.cache.max_entries, "cache");
    let mut resolver = Resolver::new(vec![test_record()?, health_record()?])
        .with_cache(cache)
        .with_forwarder(forwarder)
        .with_policy(Arc::clone(state))
        .with_fail_mode(config.filter.on_failure.mode());
    if let Some(protection) = config.security.rebinding_protection()? {
        resolver = resolver.with_rebinding_protection(protection);
    } else {
        info!("DNS rebinding protection is turned off");
    }
    Ok(resolver)
}

/// Runs the DNS server (the data plane) and the control plane until a
/// shutdown signal, upgrading on `SIGUSR2`.
async fn serve(
    config: &Config,
    config_path: &Path,
    binary: &Path,
    mut sockets: Sockets,
    secrets: &Secrets,
    child: Option<&handoff::Child>,
) -> Result<()> {
    // One signal stops both the DNS server and the API.
    let shutdown = shutdown_signal()?;
    let (stop, stopped) = watch::channel(false);
    let stop = Arc::new(stop);
    let on_shutdown = Arc::clone(&stop);
    tokio::spawn(async move {
        shutdown.await;
        on_shutdown.send_replace(true);
    });
    let mut upgrades = upgrade_signal()?;
    let state = Arc::new(PolicyState::new(Policy::none()));
    let resolver = Arc::new(resolver(config, &state)?);
    let metrics = Arc::new(metrics::Metrics::default());
    let observer_log = Arc::new(ArcSwapOption::empty());
    let server = Server::new(
        sockets.take_dns().context("the DNS sockets are missing")?,
        config.server_config(),
        Arc::clone(&resolver),
    )?
    .with_observer(Arc::new(observe::Observer::new(
        Arc::clone(&observer_log),
        Arc::clone(&metrics),
    )?));
    let data = plane::DataPlane {
        resolver,
        state,
        metrics,
        server: server.stats(),
        log: observer_log,
        started: Timestamp::now(),
    };
    let mut plane = Some(
        plane::ControlPlane::start(config, config_path, &sockets, secrets, &data, true).await?,
    );
    let mut dns = tokio::spawn(server.run(until(stopped.clone())));
    for (name, fd) in sockets.named() {
        notify::store(name, fd);
    }
    if let Some(child) = child {
        notify::took_over();
        child.serving()?;
        info!("answering in place of the previous goethite");
    } else {
        notify::ready();
    }
    let upgrade_dir = runtime_dir(config);
    // After an upgrade, the new process is the service: this one must not
    // tell systemd the service is stopping, or systemd stops the new one.
    let mut handed_over = false;
    loop {
        tokio::select! {
            finished = &mut dns => {
                finished.context("the DNS server task failed")??;
                break;
            }
            () = upgrades.next() => {
                info!("received SIGUSR2: upgrading");
                let parts = Upgrade {
                    config,
                    config_path,
                    binary,
                    dir: &upgrade_dir,
                    sockets: &sockets,
                    secrets,
                    data: &data,
                };
                match parts.run(&mut plane).await {
                    Ok(()) => {
                        info!("the new goethite answers; finishing the queries in flight");
                        handed_over = true;
                        stop.send_replace(true);
                    }
                    Err(err) => error!("the upgrade failed, carrying on: {err:#}"),
                }
            }
        }
    }
    if !handed_over {
        notify::stopping();
    }
    if let Some(plane) = plane {
        plane.stop().await?;
    }
    Ok(())
}

/// Where the upgrade's private socket goes: systemd's runtime directory
/// for the service, or the state directory.
fn runtime_dir(config: &Config) -> PathBuf {
    std::env::var_os("RUNTIME_DIRECTORY")
        .and_then(|dirs| std::env::split_paths(&dirs).next())
        .filter(|dir| dir.is_absolute())
        .unwrap_or_else(|| config.state_dir())
}

/// Everything an upgrade needs.
struct Upgrade<'a> {
    config: &'a Config,
    config_path: &'a Path,
    binary: &'a Path,
    dir: &'a Path,
    sockets: &'a Sockets,
    secrets: &'a Secrets,
    data: &'a plane::DataPlane,
}

impl Upgrade<'_> {
    /// Hands everything to a new goethite (see [`handoff`]). On success the
    /// new one answers and this one should stop; on failure this one goes
    /// on, with its control plane running again if it was stopped.
    async fn run(&self, plane: &mut Option<plane::ControlPlane>) -> Result<()> {
        use tokio::task::block_in_place;

        let mut parent =
            block_in_place(|| handoff::Parent::spawn(self.binary, self.config_path, self.dir))?;
        let sent = block_in_place(|| {
            parent.send_sockets(self.sockets, self.secrets)?;
            parent.wait_adopted()
        });
        if let Err(err) = sent {
            parent.abandon();
            return Err(err);
        }
        // The point of no return for the store: the new goethite opens it.
        if let Some(running) = plane.take()
            && let Err(err) = running.stop().await
        {
            parent.abandon();
            self.restart(plane).await;
            return Err(err);
        }
        let started = block_in_place(|| {
            parent.store_released()?;
            parent.wait_serving()
        });
        if let Err(err) = started {
            parent.abandon();
            self.restart(plane).await;
            return Err(err);
        }
        Ok(())
    }

    /// Starts the control plane again after a failed upgrade.
    async fn restart(&self, plane: &mut Option<plane::ControlPlane>) {
        match plane::ControlPlane::start(
            self.config,
            self.config_path,
            self.sockets,
            self.secrets,
            self.data,
            false,
        )
        .await
        {
            Ok(running) => *plane = Some(running),
            Err(err) => error!(
                "cannot start the control plane again: {err:#}; answering queries without it"
            ),
        }
    }
}

/// `SIGUSR2`, which asks for an upgrade.
struct Upgrades {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl Upgrades {
    /// The next request; never on platforms without `SIGUSR2`.
    async fn next(&mut self) {
        #[cfg(unix)]
        if self.signal.recv().await.is_some() {
            return;
        }
        std::future::pending::<()>().await;
    }
}

fn upgrade_signal() -> Result<Upgrades> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let signal = signal(SignalKind::user_defined2()).context("cannot handle SIGUSR2")?;
        Ok(Upgrades { signal })
    }
    #[cfg(not(unix))]
    Ok(Upgrades {})
}

/// Completes once `stopped` turns true.
async fn until(mut stopped: watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// The API's shared state, with warnings about weak setups.
fn api(
    config: &Config,
    control: &Arc<Control>,
    log: &Arc<goethite_store::QueryLog>,
    node: node::Node,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Arc<Api> {
    let token = config.api.token().ok().flatten();
    let beyond_loopback = config
        .api
        .listen
        .iter()
        .any(|addr| !addr.ip().is_loopback());
    if token.is_none() {
        warn!("no admin token is configured: any local user can use the API");
    } else if tls.is_none() && beyond_loopback {
        warn!("the API is served over plain HTTP beyond loopback: the token can be sniffed");
    }
    let web = if config.api.web_ui {
        let web = EmbeddedWeb::get();
        if web.is_none() {
            info!("this build has no web UI: build web/ before goethite to include it");
        }
        web.map(|web| Arc::new(web) as Arc<dyn WebAssets>)
    } else {
        None
    };
    let docs = if config.api.docs {
        let docs = EmbeddedDocs::get();
        if docs.is_none() {
            warn!(
                "[api] docs is on, but this build has no API reference: build web/ before goethite"
            );
        }
        docs.map(|docs| Arc::new(docs) as Arc<dyn WebAssets>)
    } else {
        None
    };
    Arc::new(Api {
        store: Arc::clone(control.store()),
        log: Arc::clone(log),
        control: Arc::new(node),
        config: ApiConfig {
            token,
            tls,
            web,
            docs,
        },
    })
}

/// The TLS settings for the API from PEM text.
fn load_tls(cert: &str, key: &str) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("cannot read the API certificate")?;
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).context("cannot read the API key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the API certificate and key do not fit together")?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

fn tui(api: Option<String>, token_file: Option<&Path>, ca_file: Option<&Path>) -> Result<()> {
    let url = api
        .or_else(|| std::env::var("GOETHITE_API").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8053".to_owned());
    let token = match token_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("cannot read the token file {}", path.display()))?
                .trim()
                .to_owned(),
        ),
        None => std::env::var("GOETHITE_TOKEN")
            .ok()
            .filter(|token| !token.is_empty()),
    };
    let ca = ca_file
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("cannot read the CA certificate {}", path.display()))
        })
        .transpose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(goethite_tui::run(goethite_tui::Options { url, token, ca }))?;
    Ok(())
}

/// Prints a new admin token and its hash.
fn token() -> Result<()> {
    let (token, hash) = goethite_api::generate_token();
    print(&format!(
        "Admin token (shown once; keep it secret, it gives full control):\n\n    {token}\n\n\
         Put its hash in the [api] table of the config file, then restart goethite:\n\n    \
         token_sha256 = \"{hash}\"\n\n\
         Clients send the token as `Authorization: Bearer <token>`.\n"
    ))
}

/// Writes `text` to standard output: command output, not a log line.
fn print(text: &str) -> Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// Loads the config, builds the upstreams and compiles the filter lists as
/// `run` would, without binding sockets or downloading anything. Unlike at
/// startup, a list file that cannot be read is an error.
fn check_config(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    if let Some(user) = &config.server.user {
        privileges::lookup(user)?;
    }
    let upstreams = config
        .upstream
        .iter()
        .map(config::UpstreamSection::to_upstream)
        .collect();
    Forwarder::new(ForwarderConfig::new(upstreams))
        .context("invalid [[upstream]] configuration")?;
    filters::check(&config.filter, &ListStore::new(config.lists_dir()))?;
    info!(config = %config_path.display(), "configuration is valid");
    Ok(())
}

/// Opens the store, creating its directory if needed.
/// The store, or, if its file cannot be used and filtering fails open, a
/// store in memory with the reason. A store locked by another goethite is
/// never worked around: that one is answering already.
fn open_store_or_fall_back(config: &Config) -> Result<(Store, Option<String>)> {
    let err = match open_store(config) {
        Ok(store) => return Ok((store, None)),
        Err(err) => err,
    };
    let locked = matches!(
        err.downcast_ref::<goethite_store::StoreError>(),
        Some(goethite_store::StoreError::Locked(_))
    );
    if locked || config.filter.on_failure == config::OnFailure::Closed {
        return Err(err);
    }
    error!(
        "{err:#}; running on a temporary store in memory, seeded from the config file, \
         until the file is fixed and goethite restarted ([filter] on_failure is \"open\")"
    );
    let store = Store::open_in_memory().context("cannot create a store in memory")?;
    Ok((
        store,
        Some(format!(
            "{err:#}: running on a temporary store in memory, seeded from the config file; \
             changes are lost when goethite stops"
        )),
    ))
}

fn open_store(config: &Config) -> Result<Store> {
    let path = config.store_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create the store directory {}", dir.display()))?;
    }
    let store = Store::open(&path).with_context(|| {
        format!(
            "cannot open the store {} (set [store] path to a writable file)",
            path.display()
        )
    })?;
    info!(path = %path.display(), "store");
    Ok(store)
}

/// A stable fingerprint of an import, to notice when `[filter]` changes.
fn fingerprint(import: &Import) -> Result<String> {
    let bytes = serde_json::to_vec(&(&import.settings, &import.lists, &import.rules))?;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Ok(format!("{hash:016x}"))
}

/// Imports `[filter]` into a store that never had it imported. After that
/// the store is the source of truth: a changed `[filter]` is only reported.
fn seed(store: &Store, config: &Config, config_path: &Path) -> Result<()> {
    let import = config.filter.to_import();
    let print = fingerprint(&import)?;
    match store.meta(IMPORTED_FILTER)? {
        None => {
            let summary = store
                .import(import, &Actor::system())
                .context("cannot import [filter] into the store")?;
            store.set_meta(IMPORTED_FILTER, &print)?;
            info!(
                lists = summary.lists_added,
                rules = summary.rules_added,
                "seeded the store from [filter] in the config file"
            );
        }
        Some(imported) if imported != print => warn!(
            config = %config_path.display(),
            "[filter] changed since it was imported, but the store is the source of truth, so \
             the change is not applied; stop goethite and run `goethite import`, or use the API"
        ),
        Some(_) => {}
    }
    Ok(())
}

/// Imports `[filter]` into the store; goethite must not be running.
fn import(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config)?;
    let import = config.filter.to_import();
    let print = fingerprint(&import)?;
    let summary = store.import(import, &Actor::cli())?;
    store.set_meta(IMPORTED_FILTER, &print)?;
    info!(
        lists_added = summary.lists_added,
        lists_updated = summary.lists_updated,
        lists_removed = summary.lists_removed,
        rules_added = summary.rules_added,
        rules_removed = summary.rules_removed,
        settings_changed = summary.settings_changed,
        "imported [filter]"
    );
    Ok(())
}

/// Re-reads the list files and recompiles the filter on every SIGHUP.
#[cfg(unix)]
fn reload_on_hangup(
    control: Arc<Control>,
    tasks: &mut tokio::task::JoinSet<()>,
    stopped: watch::Receiver<bool>,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).context("cannot handle SIGHUP")?;
    tasks.spawn(async move {
        loop {
            tokio::select! {
                received = hangup.recv() => {
                    if received.is_none() {
                        return;
                    }
                    info!("received SIGHUP, reloading filter lists");
                    control.rebuild_filter().await;
                }
                () = until(stopped.clone()) => return,
            }
        }
    });
    Ok(())
}

/// Filter reloads need SIGHUP; non-Unix platforms are for development only.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
fn reload_on_hangup(
    _control: Arc<Control>,
    _tasks: &mut tokio::task::JoinSet<()>,
    _stopped: watch::Receiver<bool>,
) -> Result<()> {
    Ok(())
}

/// Completes on the first SIGINT or SIGTERM.
#[cfg(unix)]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("cannot handle SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("cannot handle SIGTERM")?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => info!("received SIGINT"),
            _ = terminate.recv() => info!("received SIGTERM"),
        }
    })
}

/// Completes on Ctrl-C. Non-Unix platforms are for development only.
#[cfg(not(unix))]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    Ok(async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("received Ctrl-C"),
            Err(err) => {
                error!(%err, "cannot handle Ctrl-C");
                std::future::pending::<()>().await;
            }
        }
    })
}
