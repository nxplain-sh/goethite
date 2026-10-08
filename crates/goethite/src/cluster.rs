//! This node's part in a cluster: the listener its peer talks to and, on a
//! replica, following the primary's configuration.
//!
//! None of it is in the DNS path. A replica that cannot reach the primary
//! keeps answering with the configuration it has, and says so in its log.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use goethite_api::{ApiListeners, Serving, serve_router};
use goethite_cluster::server::{self, Shared};
use goethite_cluster::wire::MAX_WAIT_SECS;
use goethite_cluster::{Identity, NodeId, PeerClient, Role};
use goethite_store::{Actor, ConfigExport};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::ClusterSection;
use crate::control::Control;

/// Cluster connections served at once: the peer needs one or two.
const MAX_CONNECTIONS: usize = 8;

/// The first pause after a failed attempt to copy the configuration.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest pause between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What is read and bound before privileges are dropped: the node's keys
/// may be readable by root only.
pub struct Prepared {
    section: ClusterSection,
    identity: Identity,
    listeners: ApiListeners,
}

/// Reads this node's certificates and binds the cluster listener.
///
/// # Errors
///
/// A file that cannot be read, certificates that do not fit together, or
/// an address that cannot be bound.
pub fn prepare(section: &ClusterSection) -> Result<Prepared> {
    let read = |path: &Path, what: &str| {
        std::fs::read(path).with_context(|| format!("cannot read {what} {}", path.display()))
    };
    let identity = Identity::from_pem(
        section.node.clone(),
        &read(&section.ca, "the cluster CA")?,
        &read(&section.cert, "the node certificate")?,
        &read(&section.key, "the node key")?,
    )?;
    let listeners = ApiListeners::bind(&[section.listen])
        .with_context(|| format!("cannot bind the cluster listener on {}", section.listen))?;
    Ok(Prepared {
        section: section.clone(),
        identity,
        listeners,
    })
}

/// How following the primary goes, for status reports.
#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    /// When the primary last answered.
    pub last_contact: Option<Timestamp>,
    /// When its configuration was last copied.
    pub last_copy: Option<Timestamp>,
    /// Why the last attempt failed, if it did.
    pub error: Option<String>,
}

/// This node's cluster, running.
#[expect(dead_code, reason = "read by the cluster status API, in the next step")]
pub struct Cluster {
    /// This node.
    pub node: NodeId,
    /// The other node.
    pub peer: PeerClient,
    /// This node's role; it can change at run time.
    pub role: watch::Sender<Role>,
    /// How following the primary goes.
    pub sync: Arc<Mutex<SyncStatus>>,
}

/// Starts the cluster listener and, on a replica, following the primary,
/// until `stopped` turns true.
///
/// # Errors
///
/// If the TLS configuration cannot be built.
pub fn start(
    prepared: Prepared,
    control: &Arc<Control>,
    started_at: Timestamp,
    stopped: &watch::Receiver<bool>,
) -> Result<Cluster> {
    let Prepared {
        section,
        identity,
        listeners,
    } = prepared;
    let (role, role_rx) = watch::channel(section.role);
    let shared = Arc::new(Shared {
        node: section.node.clone(),
        role: role_rx.clone(),
        store: Arc::clone(control.store()),
        started_at,
    });
    let serving = Serving {
        name: "cluster",
        router: server::router(shared),
        tls: Some(identity.server_config(&section.peer.node)?),
        max_connections: MAX_CONNECTIONS,
    };
    let until = crate::until(stopped.clone());
    tokio::spawn(async move {
        if let Err(err) = serve_router(listeners, serving, until).await {
            error!(%err, "the cluster listener failed");
        }
    });
    let peer = PeerClient::new(
        section.peer.node.clone(),
        section.peer.address,
        identity.client_config()?,
    )
    .context("invalid peer name")?;
    let sync = Arc::new(Mutex::new(SyncStatus::default()));
    tokio::spawn(follow(
        peer.clone(),
        Arc::clone(control),
        role_rx,
        Arc::clone(&sync),
        stopped.clone(),
    ));
    info!(
        node = %section.node,
        role = %section.role,
        peer = %section.peer.node,
        peer_address = %section.peer.address,
        "cluster member"
    );
    Ok(Cluster {
        node: section.node,
        peer,
        role,
        sync,
    })
}

/// While this node is a replica, copies every new configuration from the
/// primary. Failures are logged once each and retried with a growing pause.
async fn follow(
    peer: PeerClient,
    control: Arc<Control>,
    mut role: watch::Receiver<Role>,
    sync: Arc<Mutex<SyncStatus>>,
    stopped: watch::Receiver<bool>,
) {
    let mut backoff = FIRST_BACKOFF;
    let mut last_error: Option<String> = None;
    loop {
        if *role.borrow_and_update() != Role::Replica {
            tokio::select! {
                changed = role.changed() => if changed.is_err() { return },
                () = crate::until(stopped.clone()) => return,
            }
            continue;
        }
        let have = control.store().version();
        let attempt = tokio::select! {
            result = copy_once(&peer, &control, have) => result,
            _ = role.changed() => continue,
            () = crate::until(stopped.clone()) => return,
        };
        record(&sync, &attempt);
        match attempt {
            Ok(_) => {
                if last_error.take().is_some() {
                    info!(peer = %peer.peer(), "following the primary again");
                }
                backoff = FIRST_BACKOFF;
            }
            Err(err) => {
                if last_error.as_deref() != Some(&err) {
                    warn!(
                        peer = %peer.peer(),
                        "{err}; keeping the current configuration and retrying"
                    );
                }
                last_error = Some(err);
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = crate::until(stopped.clone()) => return,
                }
                backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Notes how an attempt to follow the primary went.
fn record(sync: &Mutex<SyncStatus>, attempt: &Result<bool, String>) {
    let now = Timestamp::now();
    let mut status = sync.lock().unwrap_or_else(PoisonError::into_inner);
    match attempt {
        Ok(copied) => {
            status.last_contact = Some(now);
            if *copied {
                status.last_copy = Some(now);
            }
            status.error = None;
        }
        Err(err) => status.error = Some(err.clone()),
    }
}

/// Asks the primary for a configuration newer than `have` and applies it.
/// Returns whether one was copied.
async fn copy_once(
    peer: &PeerClient,
    control: &Arc<Control>,
    have: goethite_store::ConfigVersion,
) -> Result<bool, String> {
    let export = peer
        .config(have, MAX_WAIT_SECS)
        .await
        .map_err(|err| err.to_string())?;
    match export {
        Some(export) => apply(peer.peer(), control, export).await.map(|()| true),
        None => Ok(false),
    }
}

/// Makes `export` this node's configuration and puts it into effect.
async fn apply(
    primary: &NodeId,
    control: &Arc<Control>,
    export: ConfigExport,
) -> Result<(), String> {
    let store = Arc::clone(control.store());
    let actor = Actor::replication(primary.as_str());
    let version = export.version;
    let summary = tokio::task::spawn_blocking(move || store.replace(export, &actor))
        .await
        .map_err(|err| format!("copying the configuration failed: {err}"))?
        .map_err(|err| format!("cannot use the primary's configuration: {err}"))?;
    let Some(summary) = summary else {
        return Ok(());
    };
    info!(
        primary = %primary,
        version = version.version,
        added = summary.added,
        changed = summary.changed,
        removed = summary.removed,
        settings_changed = summary.settings_changed,
        "copied the primary's configuration"
    );
    if summary.filter_changed {
        control.rebuild_filter().await;
    } else {
        control.rebuild_policy();
    }
    if summary.lists_changed {
        control.refresh_lists();
    }
    Ok(())
}

/// `goethite cluster init`: creates the cluster's CA in `dir`.
///
/// # Errors
///
/// If a file exists already or cannot be written.
pub fn init(dir: &Path) -> Result<String> {
    let ca = goethite_cluster::certs::new_ca()?;
    let cert = dir.join("ca.crt");
    let key = dir.join("ca.key");
    write_new(&key, &ca.key, true)?;
    write_new(&cert, &ca.cert, false)?;
    Ok(format!(
        "Created the cluster CA:\n\n    {}\n    {}  (private: keep it off the nodes once \
         their certificates exist)\n\nNext, a certificate for each node:\n\n    \
         goethite cluster cert <node> --dir {}\n",
        cert.display(),
        key.display(),
        dir.display()
    ))
}

/// `goethite cluster cert`: creates a certificate for `node`, signed by the
/// CA in `dir`.
///
/// # Errors
///
/// An invalid node name, a missing CA key, or a file that exists already
/// (unless `force`) or cannot be written.
pub fn cert(dir: &Path, node: &str, force: bool) -> Result<String> {
    let node = NodeId::new(node)?;
    let ca_key_path = dir.join("ca.key");
    let ca_key = std::fs::read_to_string(&ca_key_path).with_context(|| {
        format!(
            "cannot read the CA key {}; run `goethite cluster init` first",
            ca_key_path.display()
        )
    })?;
    let pem = goethite_cluster::certs::issue(&ca_key, &node)?;
    let ca = std::fs::read(dir.join("ca.crt")).context("cannot read ca.crt next to ca.key")?;
    // The new certificate must load with the CA beside it.
    Identity::from_pem(node.clone(), &ca, pem.cert.as_bytes(), pem.key.as_bytes())
        .context("ca.crt and ca.key do not belong together")?;
    let cert = dir.join(format!("{node}.crt"));
    let key = dir.join(format!("{node}.key"));
    if force {
        for path in [&cert, &key] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| format!("cannot replace {}", path.display()));
                }
            }
        }
    }
    write_new(&key, &pem.key, true)?;
    write_new(&cert, &pem.cert, false)?;
    Ok(format!(
        "Created the certificate of {node}:\n\n    {}\n    {}  (private)\n\nCopy them and \
         ca.crt to {node}, and point its [cluster] table at them.\n",
        cert.display(),
        key.display()
    ))
}

/// Writes `contents` to a new file at `path`: never over an existing one.
/// Private files are readable by their owner only.
fn write_new(path: &Path, contents: &str, private: bool) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {} (it must not exist yet)", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))
}
