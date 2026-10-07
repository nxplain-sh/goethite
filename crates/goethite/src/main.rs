//! The goethite binary: command-line interface, configuration and wiring.

mod config;

use std::future::Future;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use goethite_resolver::{Cache, Forwarder, ForwarderConfig, Resolver, test_record};
use goethite_server::{Server, ServerConfig};
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        Command::Run { config } => run(&config),
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
        let resolver = Resolver::new(vec![test_record()?])
            .with_cache(cache)
            .with_forwarder(forwarder);
        let server = Server::bind(ServerConfig::new(config.server.listen), resolver).await?;
        server.run(shutdown).await?;
        Ok(())
    })
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
