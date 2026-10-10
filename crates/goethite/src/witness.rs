//! `goethite witness`: a cluster member that only votes.
//!
//! Two goethite nodes cannot elect a new leader once either is lost: each
//! needs the other's vote. A witness is a third voter that never stands for
//! election and serves no DNS and no API, so it can run on anything small,
//! such as a router, a NAS or a container. It keeps the cluster's log and
//! configuration in its own store, like every member, and talks to the
//! others over the cluster channel only.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use goethite_api::{ApiListeners, HANDSHAKE_TIMEOUT, Serving, serve_router};
use goethite_cluster::raft::node::RaftNode;
use goethite_cluster::raft::{members_of, state_of};
use goethite_cluster::server::{self, Shared};
use goethite_cluster::{Identity, NodeId, Peers};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{ClusterSection, Config};
use crate::secrets::Secrets;
use crate::{notify, sandbox};

/// Cluster connections served at once.
const MAX_CONNECTIONS: usize = 32;

/// How often the witness looks at the cluster.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// Runs the witness for the config file at `config_path` until SIGINT or
/// SIGTERM.
///
/// # Errors
///
/// If the config file has no usable `[cluster]` table, the store cannot be
/// opened, or the cluster listener cannot be bound.
pub(crate) fn run(config_path: &Path) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "starting goethite witness"
    );
    let config = Config::load_witness(config_path)?;
    let section = config.cluster.clone().with_context(|| {
        format!(
            "{} has no [cluster] table: a witness is a member of a cluster",
            config_path.display()
        )
    })?;
    if section.bootstraps(None, None) {
        bail!(
            "cluster.bootstrap (or role = \"primary\") is set, but a witness never leads, so it \
             cannot start the cluster: set it on a goethite node"
        );
    }
    let pem = Secrets::read(&config)?
        .cluster
        .context("the cluster's certificates are missing")?;
    let identity = Identity::from_pem(
        section.node.clone(),
        pem.ca.as_bytes(),
        pem.node.cert.as_bytes(),
        pem.node.key.as_bytes(),
    )?;
    let listeners = ApiListeners::bind(&[section.listen])?;
    let store = crate::open_store(&config)?;
    if config.security.sandbox {
        sandbox::apply(&sandbox::Policy::witness(&config))?;
    } else {
        warn!("the sandbox is turned off ([security] sandbox = false)");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(async move {
        let shutdown = crate::shutdown_signal()?;
        let store = Arc::new(store);
        let raft = RaftNode::start(
            section.node.clone(),
            section.listen,
            true,
            Arc::clone(&store),
            identity.client_config()?,
        )
        .await
        .context("cannot start Raft")?;
        let peers = Peers::default();
        let shared = Arc::new(Shared {
            node: section.node.clone(),
            witness: true,
            raft: Arc::clone(raft.shared()),
            store,
            log: None,
            started_at: Timestamp::now(),
        });
        let serving = Serving {
            name: "cluster",
            router: server::router(shared),
            tls: Some(identity.server_config(peers.clone())?),
            max_connections: MAX_CONNECTIONS,
            first_request_timeout: HANDSHAKE_TIMEOUT,
        };
        let (stop, stopped) = watch::channel(false);
        let serve = tokio::spawn(serve_router(
            listeners,
            serving,
            crate::until(stopped.clone()),
        ));
        let watching = tokio::spawn(watch_cluster(Arc::clone(&raft), peers, section, stopped));
        notify::ready();
        shutdown.await;
        notify::stopping();
        stop.send_replace(true);
        raft.shutdown().await;
        let _ = watching.await;
        serve
            .await
            .context("the cluster listener failed")?
            .context("the cluster listener failed")?;
        info!("stopped");
        Ok(())
    })
}

/// Lets the members in the config file and in the cluster connect, and logs
/// the cluster's leader as it changes, until `stopped` turns true.
async fn watch_cluster(
    raft: Arc<RaftNode>,
    peers: Peers,
    section: ClusterSection,
    stopped: watch::Receiver<bool>,
) {
    let mut last_leader: Option<Option<NodeId>> = None;
    loop {
        let metrics = raft.metrics();
        let mut nodes: BTreeSet<NodeId> = section
            .members()
            .map(|member| member.node.clone())
            .collect();
        if let Some(metrics) = &metrics {
            nodes.extend(
                members_of(metrics)
                    .iter()
                    .filter_map(|recorded| recorded.member.node().ok()),
            );
        }
        nodes.insert(section.node.clone());
        peers.set(nodes);
        let (_, term, leader) = state_of(metrics.as_ref());
        if last_leader.as_ref() != Some(&leader) {
            match &leader {
                Some(leader) => info!(%leader, term, "the cluster's leader"),
                None if raft.cluster().is_some() => warn!("the cluster has no leader"),
                None => info!("waiting for the cluster's leader to add this witness"),
            }
            last_leader = Some(leader);
        }
        tokio::select! {
            () = tokio::time::sleep(CHECK_EVERY) => {}
            () = crate::until(stopped.clone()) => return,
        }
    }
}
