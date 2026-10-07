//! The goethite binary: command-line interface, configuration and wiring.

mod config;
mod download;
mod filters;
mod lists;
mod privileges;

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use goethite_resolver::{
    Blocking, Cache, Forwarder, ForwarderConfig, Resolver, TlsRoots, test_record, tls_client_config,
};
use goethite_server::{Listeners, Server};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::config::Config;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        Command::Run { config } => run(&config),
        Command::CheckConfig { config } => check_config(&config),
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

fn run(config_path: &Path) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "starting goethite"
    );
    let config = Config::load(config_path)?;
    let account = config
        .server
        .user
        .as_deref()
        .map(privileges::lookup)
        .transpose()?;
    let server_config = config.server.to_server_config();
    // Bound while the process is still single-threaded, before the runtime
    // starts, so privileges can be dropped once the sockets exist.
    let listeners = Listeners::bind(&server_config)?;
    privileges::drop_privileges(account.as_ref())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;

    runtime.block_on(async {
        // Install signal handlers before binding so a signal is never missed.
        let shutdown = shutdown_signal()?;
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
            .with_forwarder(forwarder);
        if let Some(protection) = config.security.rebinding_protection()? {
            resolver = resolver.with_rebinding_protection(protection);
        } else {
            info!("DNS rebinding protection is turned off");
        }
        let mut blocking = None;
        if config.filter.enabled {
            let section = config.filter.clone();
            let filter = tokio::task::spawn_blocking(move || filters::build(&section))
                .await
                .context("building the filter failed")?;
            let shared = Arc::new(Blocking::new(
                filter,
                config.filter.block_response.to_block_response(),
                config.filter.blocked_ttl,
            ));
            reload_on_hangup(Arc::clone(&shared), config.filter.clone())?;
            resolver = resolver.with_blocking(Arc::clone(&shared));
            blocking = Some(shared);
        } else {
            info!("filtering is turned off");
        }
        let resolver = Arc::new(resolver);
        if let Some(blocking) = blocking {
            let tls = tls_client_config(&TlsRoots::Bundled, &[b"h2", b"http/1.1"])?;
            let downloader =
                download::Downloader::new(Arc::clone(&resolver), tls, filters::MAX_LIST_LEN);
            filters::spawn_updates(blocking, config.filter.clone(), downloader);
        }
        let server = Server::new(listeners, server_config, Arc::clone(&resolver))?;
        server.run(shutdown).await?;
        Ok(())
    })
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
    if config.filter.enabled {
        filters::check(&config.filter)?;
    }
    info!(config = %config_path.display(), "configuration is valid");
    Ok(())
}

/// Rebuilds the filter from the list files on every SIGHUP. The config file
/// itself is not re-read.
#[cfg(unix)]
fn reload_on_hangup(blocking: Arc<Blocking>, section: config::FilterSection) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).context("cannot handle SIGHUP")?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            info!("received SIGHUP, reloading filter lists");
            filters::reload(&blocking, section.clone()).await;
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
fn reload_on_hangup(_blocking: Arc<Blocking>, _section: config::FilterSection) -> Result<()> {
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
