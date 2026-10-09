//! `goethite vrrp`: holding the floating IP when this node should.
//!
//! It is its own process, beside `goethite run`, so the DNS server never
//! holds the capabilities it needs: `CAP_NET_RAW` to open its raw and
//! packet sockets, and `CAP_NET_ADMIN` to add and remove the address. It
//! opens its sockets, gives up `CAP_NET_RAW`, and then checks the DNS
//! server once a second ([`HEALTH_NAME`]) while
//! [`goethite_cluster::vrrp`] runs VRRP with the peer.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use goethite_proto::{
    DnsCodec, HickoryCodec, Query, Question, RecordClass, RecordType, ResponseCode,
};
use goethite_resolver::HEALTH_NAME;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::Config;

/// How often goethite is checked.
const CHECK_EVERY: Duration = Duration::from_secs(1);

/// How long an answer may take.
const CHECK_TIMEOUT: Duration = Duration::from_secs(1);

/// Failed checks in a row before goethite counts as down: one lost
/// datagram is not an outage.
const FALL: u32 = 3;

/// Passed checks in a row before it counts as up again.
const RISE: u32 = 2;

/// Runs the floating IP for the config file at `config_path` until SIGINT
/// or SIGTERM.
pub(crate) fn run(config_path: &Path) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "starting goethite vrrp"
    );
    let config = Config::load(config_path)?;
    let section = config.vrrp.as_ref().with_context(|| {
        format!(
            "{} has no [vrrp] table: goethite vrrp has no floating IP to hold",
            config_path.display()
        )
    })?;
    let check = section
        .check_address(&config.server)
        .context("nothing to check goethite on")?;
    imp::run(section.to_vrrp_config(), check, config.security.sandbox)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::net::SocketAddr;

    use anyhow::{Context, Result};
    use goethite_cluster::vrrp::{Vrrp, VrrpConfig};
    use tokio::sync::watch;

    use crate::{notify, privileges, sandbox};

    pub(super) fn run(config: VrrpConfig, check: SocketAddr, confine: bool) -> Result<()> {
        let vrrp = Vrrp::open(config)?;
        // Sockets open: only changing addresses needs a privilege now.
        privileges::keep_net_admin()?;
        if confine {
            sandbox::apply(&sandbox::Policy::vrrp())?;
        } else {
            tracing::warn!("the sandbox is turned off ([security] sandbox = false)");
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot start the async runtime")?;
        runtime.block_on(async move {
            let shutdown = crate::shutdown_signal()?;
            let (healthy, health) = watch::channel(false);
            let checks = tokio::spawn(super::check_health(check, healthy));
            notify::ready();
            let result = vrrp.run(health, shutdown).await;
            notify::stopping();
            checks.abort();
            result.context("the floating IP failed")
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::net::SocketAddr;

    use anyhow::{Result, bail};
    use goethite_cluster::vrrp::VrrpConfig;

    pub(super) fn run(_config: VrrpConfig, _check: SocketAddr, _confine: bool) -> Result<()> {
        bail!("goethite vrrp needs Linux; other platforms are for development only")
    }
}

/// Checks goethite at `target` once a second, and says on `healthy`
/// whether it answers, after [`FALL`] failures or [`RISE`] successes in a
/// row. Runs until aborted.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "goethite vrrp runs on Linux only")
)]
async fn check_health(target: SocketAddr, healthy: watch::Sender<bool>) {
    let mut streak = Streak::default();
    let mut ticks = tokio::time::interval(CHECK_EVERY);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let result = match tokio::time::timeout(CHECK_TIMEOUT, ask(target)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("no answer within {CHECK_TIMEOUT:?}")),
        };
        if let Err(err) = &result {
            debug!(%target, "health check failed: {err:#}");
        }
        if let Some(up) = streak.record(result.is_ok()) {
            if up {
                info!(%target, "goethite answers its health checks");
            } else if let Err(err) = &result {
                warn!(%target, "goethite does not answer its health checks: {err:#}");
            }
            healthy.send_replace(up);
        }
    }
}

/// Asks goethite at `target` for [`HEALTH_NAME`]: any well-formed
/// `NOERROR` answer to the question passes.
async fn ask(target: SocketAddr) -> Result<()> {
    let local = if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(target).await?;
    let query = Query {
        id: rand::random(),
        recursion_desired: true,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name: HEALTH_NAME.parse()?,
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        },
        edns: None,
    };
    let codec = HickoryCodec;
    let mut wire = Vec::new();
    codec.encode_query(&query, &mut wire)?;
    socket.send(&wire).await?;
    let mut buffer = [0; 512];
    loop {
        let len = socket.recv(&mut buffer).await?;
        let Ok(answer) = codec.decode_response(buffer.get(..len).unwrap_or_default()) else {
            continue;
        };
        if answer.id != query.id || answer.question.as_ref() != Some(&query.question) {
            continue;
        }
        anyhow::ensure!(
            answer.rcode == ResponseCode::NO_ERROR,
            "answered {:?}",
            answer.rcode
        );
        return Ok(());
    }
}

/// Health from check results, changing only after a run of the opposite
/// result.
#[derive(Debug, Default)]
struct Streak {
    healthy: bool,
    run: u32,
}

impl Streak {
    /// Records a result: the new health, if it changed.
    fn record(&mut self, passed: bool) -> Option<bool> {
        if passed == self.healthy {
            self.run = 0;
            return None;
        }
        self.run = self.run.saturating_add(1);
        let needed = if self.healthy { FALL } else { RISE };
        if self.run < needed {
            return None;
        }
        self.healthy = passed;
        self.run = 0;
        Some(passed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_changes_after_a_run() {
        let mut streak = Streak::default();
        // Starts down; up after two passes in a row.
        assert_eq!(streak.record(true), None);
        assert_eq!(streak.record(false), None);
        assert_eq!(streak.record(true), None);
        assert_eq!(streak.record(true), Some(true));
        assert_eq!(streak.record(true), None);
        // Down after three failures in a row, not two.
        assert_eq!(streak.record(false), None);
        assert_eq!(streak.record(false), None);
        assert_eq!(streak.record(true), None);
        assert_eq!(streak.record(false), None);
        assert_eq!(streak.record(false), None);
        assert_eq!(streak.record(false), Some(false));
    }

    #[tokio::test]
    async fn asks_a_server() {
        use std::sync::Arc;

        use goethite_resolver::{Resolver, health_record};
        use goethite_server::{Listeners, Server, ServerConfig};

        let config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
        let listeners = Listeners::bind(&config).unwrap();
        let addr = listeners.udp_local_addrs().unwrap()[0];
        let resolver = Arc::new(Resolver::new(vec![health_record().unwrap()]));
        let server = Server::new(listeners, config, resolver).unwrap();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(server.run(crate::until(stopped)));
        ask(addr).await.unwrap();

        // Without the record: an answer, but not NOERROR.
        let config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
        let listeners = Listeners::bind(&config).unwrap();
        let other = listeners.udp_local_addrs().unwrap()[0];
        let server = Server::new(listeners, config, Arc::new(Resolver::new(Vec::new()))).unwrap();
        let other_task = tokio::spawn(server.run(crate::until(stop.subscribe())));
        assert!(ask(other).await.is_err());

        stop.send_replace(true);
        task.await.unwrap().unwrap();
        other_task.await.unwrap().unwrap();
    }
}
