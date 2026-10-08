//! The goethite binary: command-line interface, configuration and wiring.

mod config;
mod control;
mod download;
mod filters;
mod lists;
mod metrics;
mod node;
mod observe;
mod privileges;

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use goethite_api::{Api, ApiConfig, ApiListeners};
use goethite_resolver::{
    Cache, Forwarder, ForwarderConfig, Policy, PolicyState, Resolver, TlsRoots, test_record,
    tls_client_config,
};
use goethite_server::{Listeners, Server};
use goethite_store::{Actor, Import, Store};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::config::Config;
use crate::control::Control;
use crate::lists::ListStore;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        Command::Run { config } => run(&config),
        Command::CheckConfig { config } => check_config(&config),
        Command::Import { config } => import(&config),
        Command::Token => token(),
        Command::Openapi => print(&goethite_api::openapi_json()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
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
        .try_init();
}

/// What is set up while goethite may still be privileged, before any
/// thread starts.
struct Prepared {
    listeners: Listeners,
    server_config: goethite_server::ServerConfig,
    api_listeners: Option<ApiListeners>,
    api_tls: Option<Arc<rustls::ServerConfig>>,
    store: Arc<Store>,
    query_log: Arc<goethite_store::QueryLog>,
}

fn run(config_path: &Path) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "starting goethite"
    );
    let config = Config::load(config_path)?;
    let prepared = prepare(&config, config_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(serve(&config, prepared))
}

/// Binds every socket and reads the API key while the process is still
/// single-threaded and maybe privileged, drops privileges, then opens the
/// store as the user goethite runs as, so its files are its own.
fn prepare(config: &Config, config_path: &Path) -> Result<Prepared> {
    let account = config
        .server
        .user
        .as_deref()
        .map(privileges::lookup)
        .transpose()?;
    let server_config = config.server.to_server_config();
    let listeners = Listeners::bind(&server_config)?;
    let api_listeners = config
        .api
        .enabled
        .then(|| ApiListeners::bind(&config.api.listen))
        .transpose()?;
    let api_tls = match (&config.api.tls_cert, &config.api.tls_key) {
        (Some(cert), Some(key)) if config.api.enabled => Some(load_tls(cert, key)?),
        _ => None,
    };
    privileges::drop_privileges(account.as_ref())?;
    let store = Arc::new(open_store(config)?);
    seed(&store, config, config_path)?;
    let upstream_names = config
        .upstream
        .iter()
        .map(|upstream| upstream.to_upstream().address.to_string())
        .collect();
    let query_log = store.start_query_log(config.querylog.to_config(), upstream_names)?;
    if !config.querylog.enabled {
        info!("the query log is turned off; statistics are still kept");
    }
    Ok(Prepared {
        listeners,
        server_config,
        api_listeners,
        api_tls,
        store,
        query_log,
    })
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
    let mut resolver = Resolver::new(vec![test_record()?])
        .with_cache(cache)
        .with_forwarder(forwarder)
        .with_policy(Arc::clone(state));
    if let Some(protection) = config.security.rebinding_protection()? {
        resolver = resolver.with_rebinding_protection(protection);
    } else {
        info!("DNS rebinding protection is turned off");
    }
    Ok(resolver)
}

/// Runs the DNS server, the control plane and the API until a shutdown
/// signal.
async fn serve(config: &Config, prepared: Prepared) -> Result<()> {
    // One signal stops both the DNS server and the API.
    let shutdown = shutdown_signal()?;
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        stop.send_replace(true);
    });
    let state = Arc::new(PolicyState::new(Policy::none()));
    let resolver = Arc::new(resolver(config, &state)?);
    let control = Control::new(prepared.store, state, ListStore::new(config.lists_dir()));
    // Filter from the first query on, with the lists already on disk.
    control.rebuild_filter().await;
    if !control.store().config().settings.spec.protection {
        info!("filtering is turned off in the settings");
    }
    reload_on_hangup(Arc::clone(&control))?;
    let tls = tls_client_config(&TlsRoots::Bundled, &[b"h2", b"http/1.1"])?;
    let downloader = download::Downloader::new(Arc::clone(&resolver), tls, filters::MAX_LIST_LEN);
    control.spawn(downloader);
    let metrics = Arc::new(metrics::Metrics::default());
    let server = Server::new(
        prepared.listeners,
        prepared.server_config,
        Arc::clone(&resolver),
    )?
    .with_observer(Arc::new(observe::Observer {
        log: Arc::clone(&prepared.query_log),
        metrics: Arc::clone(&metrics),
    }));
    let api = prepared.api_listeners.map(|listeners| {
        let node = node::Node {
            control: Arc::clone(&control),
            resolver: Arc::clone(&resolver),
            server: server.stats(),
            metrics,
            log: Arc::clone(&prepared.query_log),
            querylog_enabled: config.querylog.enabled,
            started: Timestamp::now(),
        };
        let api = api(
            config,
            &control,
            &prepared.query_log,
            node,
            prepared.api_tls,
        );
        tokio::spawn(goethite_api::serve(listeners, api, until(stopped.clone())))
    });
    server.run(until(stopped)).await?;
    if let Some(api) = api {
        api.await.context("the API task failed")??;
    }
    Ok(())
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
    Arc::new(Api {
        store: Arc::clone(control.store()),
        log: Arc::clone(log),
        control: Arc::new(node),
        config: ApiConfig { token, tls },
    })
}

/// The TLS settings for the API from PEM files.
fn load_tls(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("cannot read the API certificate {}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("cannot read the API key {}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the API certificate and key do not fit together")?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
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
fn reload_on_hangup(control: Arc<Control>) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).context("cannot handle SIGHUP")?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            info!("received SIGHUP, reloading filter lists");
            control.rebuild_filter().await;
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
fn reload_on_hangup(_control: Arc<Control>) -> Result<()> {
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
