//! The goethite binary: command-line interface, configuration and wiring.

mod certs;
mod cluster;
mod config;
mod connect;
mod control;
mod download;
mod filterlists;
mod filters;
mod handoff;
mod lists;
mod migrate;
mod node;
mod notify;
mod observe;
mod plane;
mod privileges;
mod sandbox;
mod secrets;
mod services;
mod sizes;
mod sockets;
mod telemetry;
mod vrrp;
mod witness;

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use clap::{Parser, Subcommand};
use goethite_api::leak::LeakTests;
use goethite_api::{Api, ApiConfig, EmbeddedDocs, EmbeddedWeb, WebAssets};
use goethite_resolver::{
    Cache, Forwarder, ForwarderConfig, Policy, PolicyState, Recursor, Resolver, health_record,
    test_record,
};
use goethite_server::Server;
use goethite_store::{
    Actor, DEFAULT_GROUP, Group, GroupList, Import, List, ListSpec, ManagedBy, Store,
};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

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
    /// Create the certificates a cluster's members use to recognize each
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
    /// Vote in a cluster without serving DNS: a third member for two
    /// goethite nodes, so the cluster can elect a new leader when either
    /// is lost. Runs until SIGINT or SIGTERM.
    Witness {
        /// Path to the TOML configuration file, with a `[cluster]` table.
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
    },
    /// Open the terminal UI for a goethite node, through its API.
    Tui {
        #[command(flatten)]
        api: ApiArgs,
    },
    /// Bring a Pi-hole's or an AdGuard Home's configuration over, through
    /// their API and goethite's. Shows what would change; `--apply` makes
    /// the changes. Running it again adds only what is still missing.
    Migrate {
        #[command(subcommand)]
        from: MigrateFrom,
    },
}

/// How to reach a goethite node's API.
#[derive(Debug, clap::Args)]
struct ApiArgs {
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
}

#[derive(Debug, Subcommand)]
enum MigrateFrom {
    /// From Pi-hole v6: lists, exact domains, groups, clients, local DNS and
    /// CNAME records, the blocking mode.
    Pihole(MigrateArgs),
    /// From AdGuard Home: lists, custom rules, clients and their settings,
    /// DNS rewrites, safe search, blocked services, access lists, the
    /// blocking mode.
    AdguardHome(MigrateArgs),
}

#[derive(Debug, clap::Args)]
struct MigrateArgs {
    /// The old server's web address, such as `http://pi.hole` or
    /// `http://192.168.1.2:3000`.
    #[arg(long, value_name = "URL")]
    from: String,
    /// AdGuard Home's user name (default `admin`).
    #[arg(long)]
    user: Option<String>,
    /// A file holding the old server's password: for Pi-hole, its web
    /// password or an app password. None for a server without one.
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
    /// A PEM CA certificate, for an old server that serves HTTPS with its
    /// own.
    #[arg(long, value_name = "PATH")]
    from_ca_file: Option<PathBuf>,
    /// Make the changes in goethite; without it, only show them.
    #[arg(long)]
    apply: bool,
    #[command(flatten)]
    api: ApiArgs,
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
        Command::Witness { config } => witness::run(&config),
        Command::Token => token(),
        Command::Openapi => print(&goethite_api::openapi_json()),
        Command::Cluster { command } => match command {
            ClusterCommand::Init { dir } => cluster::init(&dir).and_then(|text| print(&text)),
            ClusterCommand::Cert { node, dir, force } => {
                cluster::cert(&dir, &node, force).and_then(|text| print(&text))
            }
        },
        Command::Tui { api } => tui(&api),
        Command::Migrate { from } => match from {
            MigrateFrom::Pihole(args) => migrate(migrate::From::Pihole, args),
            MigrateFrom::AdguardHome(args) => migrate(migrate::From::AdguardHome, args),
        },
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
///
/// openraft logs its elections and membership changes at `info`, with its
/// internal state and members' raw numbers. goethite logs the same events
/// itself, by name, so openraft logs only warnings and errors unless
/// `RUST_LOG` names it.
fn init_logging() {
    let directives = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default();
    let mut filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(&directives);
    for (name, quiet) in [
        ("hickory", "hickory_proto=off"),
        ("openraft", "openraft=warn"),
    ] {
        if !directives.contains(name)
            && let Ok(quiet) = quiet.parse()
        {
            filter = filter.add_directive(quiet);
        }
    }
    let stderr = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        // Otherwise a log line that cannot be written (nothing reads standard
        // error any more) is reported with `eprintln!`, which panics: the
        // process dies, or the task that logged does, such as the one that
        // stops goethite on SIGTERM. A lost log line must cost nothing more.
        .log_internal_errors(false)
        .with_filter(filter);
    // Only fails if a global subscriber is already set, which never happens here.
    let _ = tracing_subscriber::registry()
        .with(stderr)
        .with(telemetry::logs::LogExport.with_filter(telemetry::logs::filter()))
        .with(telemetry::traces::layer())
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
    confine(config, config_path, binary)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(serve(config, config_path, binary, sockets, &secrets, child))
}

/// Confines `goethite run` (see [`sandbox`]), unless `[security] sandbox`
/// is off. The directories it may change are created first, if they can
/// be: rules can only name what exists. One that cannot be created now
/// could not be written later either, so that is left to whatever needs it.
fn confine(config: &Config, config_path: &Path, binary: &Path) -> Result<()> {
    if !config.security.sandbox {
        warn!("the sandbox is turned off ([security] sandbox = false)");
        return Ok(());
    }
    let store_dir = config.store_path().parent().map(Path::to_path_buf);
    for dir in store_dir.iter().chain([&config.lists_dir()]) {
        if let Err(err) = std::fs::create_dir_all(dir) {
            tracing::debug!(dir = %dir.display(), %err, "cannot create it before the sandbox");
        }
    }
    sandbox::apply(&sandbox::Policy::run(
        config,
        config_path,
        binary,
        &runtime_dir(config),
    ))
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
    let cache = Cache::new(config.cache.to_cache_config());
    info!(max_entries = config.cache.max_entries, "cache");
    let mut resolver = Resolver::new(vec![test_record()?, health_record()?]).with_cache(cache);
    if config.recursion.enabled {
        let recursion = config.recursion.to_recursor_config(has_ipv6_route);
        info!(
            qname_minimisation = recursion.qname_minimisation,
            ipv6 = recursion.ipv6,
            dnssec = recursion.dnssec,
            "resolving from the root servers"
        );
        resolver = resolver.with_recursor(Recursor::new(recursion));
    } else {
        resolver = resolver.with_forwarder(forwarder(config)?);
    }
    let mut resolver = resolver
        .with_policy(Arc::clone(state))
        .with_fail_mode(config.filter.on_failure.mode())
        .with_span_details(config.telemetry.query_details);
    if let Some(protection) = config.security.rebinding_protection()? {
        resolver = resolver.with_rebinding_protection(protection);
    } else {
        info!("DNS rebinding protection is turned off");
    }
    Ok(resolver)
}

/// The forwarder for `config`'s `[[upstream]]` tables.
fn forwarder(config: &Config) -> Result<Forwarder> {
    let upstreams: Vec<_> = config
        .upstream
        .iter()
        .map(config::UpstreamSection::to_upstream)
        .collect();
    for upstream in &upstreams {
        info!(address = %upstream.address, transport = ?upstream.transport, "upstream");
    }
    Forwarder::new(ForwarderConfig::new(upstreams)).context("invalid [[upstream]] configuration")
}

/// Whether this host has a route to the IPv6 internet: a UDP socket can be
/// connected to a root server's IPv6 address. Nothing is sent.
fn has_ipv6_route() -> bool {
    std::net::UdpSocket::bind("[::]:0")
        .and_then(|socket| socket.connect("[2001:503:ba3e::2:30]:53"))
        .is_ok()
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
    let telemetry = telemetry::Telemetry::from_config(config, secrets, &resolver)?;
    let observer_log = Arc::new(ArcSwapOption::empty());
    let leak = Arc::new(LeakTests::new());
    let mut server = Server::new(
        sockets.take_dns().context("the DNS sockets are missing")?,
        config.server_config(),
        Arc::clone(&resolver),
    )?
    .with_observer(Arc::new(observe::Observer::new(
        Arc::clone(&observer_log),
        telemetry.queries(),
        Arc::clone(&leak),
    )?));
    let dns_cert = match (&config.server.tls, &secrets.dns_tls) {
        (Some(tls), Some(pem)) => {
            let files = Some((tls.cert.clone(), tls.key.clone()));
            let cert = certs::Served::new("DNS certificate", pem, files)?;
            // Each listener offers its own ALPN protocols.
            server = server.with_tls(cert.server_config(&[])?);
            Some(cert)
        }
        (Some(_), None) => anyhow::bail!("the DNS certificate is missing"),
        (None, _) => None,
    };
    telemetry.observe(&resolver, &server.stats());
    let data = plane::DataPlane {
        resolver,
        state,
        telemetry: Arc::new(telemetry),
        log: observer_log,
        dns_cert,
        started: Timestamp::now(),
        leak,
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
    // A last export, while the control plane's metrics are still there. It
    // waits on a task on this runtime.
    tokio::task::block_in_place(|| data.telemetry.shutdown());
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
    node: Arc<node::Node>,
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
        control: node,
        config: ApiConfig {
            token,
            tls,
            web,
            docs,
        },
    })
}

fn tui(api: &ApiArgs) -> Result<()> {
    let (url, token, ca) = api_options(api)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(goethite_tui::run(goethite_tui::Options { url, token, ca }))?;
    Ok(())
}

/// Reads the old server's configuration, shows the plan, and applies it
/// with `--apply`.
fn migrate(from: migrate::From, args: MigrateArgs) -> Result<()> {
    let password = args
        .password_file
        .as_deref()
        .map(migrate::read_password)
        .transpose()?;
    let ca = args
        .from_ca_file
        .as_deref()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("cannot read the CA certificate {}", path.display()))
        })
        .transpose()?;
    let source = migrate::Source {
        from,
        url: args.from,
        user: args.user,
        password,
        ca,
    };
    let target = if args.apply {
        let (url, token, ca) = api_options(&args.api)?;
        Some(goethite_tui::Client::new(&url, token, ca.as_deref())?)
    } else {
        None
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    let report = runtime.block_on(migrate::migrate(source, target))?;
    print(&report)
}

/// The API address, token and CA certificate from the options, the
/// environment and the defaults.
fn api_options(api: &ApiArgs) -> Result<(String, Option<String>, Option<Vec<u8>>)> {
    let url = api
        .api
        .clone()
        .or_else(|| std::env::var("GOETHITE_API").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8053".to_owned());
    let token = match api.token_file.as_deref() {
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
    let ca = api
        .ca_file
        .as_deref()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("cannot read the CA certificate {}", path.display()))
        })
        .transpose()?;
    Ok((url, token, ca))
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
    if !config.recursion.enabled {
        forwarder(&config)?;
    }
    filters::check(
        &config.filter,
        &ListStore::new(config.lists_dir(), config.local_lists_dir()),
    )?;
    if let Some(services::ServicesFrom::File(path)) = config.filter.services_from() {
        match services::read(&path, None)? {
            services::Read::Changed(catalog) => {
                info!(services = catalog.services.len(), "services catalog ready");
            }
            services::Read::Missing | services::Read::Unchanged => {
                anyhow::bail!("filter.services_file: {} does not exist", path.display());
            }
        }
    }
    let secrets = Secrets::read(&config)?;
    if let Some(pem) = &secrets.api_tls {
        certs::Served::new("API certificate", pem, None)?;
    }
    if let Some(pem) = &secrets.dns_tls {
        certs::Served::new("DNS certificate", pem, None)?;
    }
    if let Some(text) = &secrets.telemetry_headers {
        telemetry::otlp::headers(text)?;
    }
    telemetry::otlp::roots(secrets.telemetry_ca.as_deref())?;
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
            if config.filter.default_lists && config.filter.list.is_empty() {
                add_default_lists(store)?;
            }
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

/// Adds goethite's default lists (the default preset's) to a new store,
/// used by the default group. They are ordinary lists: the API or the UIs
/// may change or remove them, and `goethite import` leaves them alone.
fn add_default_lists(store: &Store) -> Result<()> {
    let actor = Actor::system();
    let mut ids = Vec::new();
    for default in goethite_api::recommended::default_lists() {
        let list = store.create::<List>(
            ListSpec {
                name: default.name.to_owned(),
                url: Some(default.url.to_owned()),
                path: None,
                enabled: true,
                comment: format!(
                    "One of goethite's default lists ({}): keep it, replace it or add others.",
                    default.license
                ),
                managed_by: ManagedBy::Api,
            },
            &actor,
        )?;
        info!(
            list = default.name,
            "a new store: filtering with a default list"
        );
        ids.push(list.id);
    }
    if ids.is_empty() {
        return Ok(());
    }
    let group = store
        .get::<Group>(DEFAULT_GROUP)
        .context("the default group is missing")?;
    let mut spec = group.spec;
    spec.lists.extend(ids.into_iter().map(|list| GroupList {
        list,
        schedule: None,
    }));
    store.update::<Group>(DEFAULT_GROUP, spec, Some(group.revision), &actor)?;
    Ok(())
}

/// Imports `[filter]` into the store; goethite must not be running.
fn import(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let store = open_store(&config)?;
    if store.cluster_value("id")?.is_some() {
        bail!(
            "this node is in a cluster, whose configuration every member keeps alike: change it \
             through the API of any member, not with goethite import"
        );
    }
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
    certs: Vec<Arc<certs::Served>>,
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
                    info!("received SIGHUP, reloading filter lists and certificates");
                    for cert in &certs {
                        cert.reload_and_log();
                    }
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
    _certs: Vec<Arc<certs::Served>>,
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
