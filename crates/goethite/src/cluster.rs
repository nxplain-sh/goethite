//! This node's part in a cluster: the listener its peer talks to, following
//! the primary on a replica, forwarding configuration changes to it, and
//! changing roles.
//!
//! None of it is in the DNS path. A replica that cannot reach the primary
//! keeps answering with the configuration it has, and says so in its log
//! and its status.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};
use goethite_api::{
    Api, ApiError, ApiListeners, ClusterRole, ClusterStatus, Forwarded, ForwardedAnswer,
    PeerStatus, Serving, SyncStatus, Writes, serve_router,
};
use goethite_cluster::server::{self, Shared};
use goethite_cluster::wire::{API_PATH, MAX_WAIT_SECS, NodeInfo, WireError};
use goethite_cluster::{ClientError, Identity, NodeId, PeerClient, Role};
use goethite_store::{
    Actor, AuditAction, ConfigExport, ConfigVersion, QueryLog, StatsReport, Store,
};
use jiff::Timestamp;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::ClusterSection;
use crate::control::Control;

/// Cluster connections served at once: the peer needs a few.
const MAX_CONNECTIONS: usize = 8;

/// The first pause after a failed attempt to copy the configuration.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest pause between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How often each node checks on the other.
const HEARTBEAT: Duration = Duration::from_secs(5);

/// The largest forwarded change: an API body and its envelope.
const MAX_FORWARD: usize = 2 * 1024 * 1024;

/// The store's `meta` keys of a role changed at run time, and of the role
/// the config file gave when it was changed.
const ROLE_KEY: &str = "cluster_role";
const ROLE_BASE_KEY: &str = "cluster_role_base";

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

/// The other node, as last checked.
#[derive(Clone, Debug, Default)]
struct PeerState {
    checked_at: Option<Timestamp>,
    info: Option<NodeInfo>,
    error: Option<String>,
}

/// This node's cluster, running.
pub struct Cluster {
    node: NodeId,
    peer: PeerClient,
    peer_address: String,
    role: watch::Sender<Role>,
    config_role: Role,
    store: Arc<Store>,
    peer_state: Mutex<PeerState>,
    sync: Mutex<SyncStatus>,
    /// The API, to run changes forwarded by the replica; set once it
    /// exists.
    api: OnceLock<Arc<Api>>,
}

/// Starts the cluster listener, the heartbeat and, on a replica, following
/// the primary, until `stopped` turns true.
///
/// # Errors
///
/// If the TLS configuration cannot be built or the store cannot be read.
pub fn start(
    prepared: Prepared,
    control: &Arc<Control>,
    log: &Arc<QueryLog>,
    started_at: Timestamp,
    stopped: &watch::Receiver<bool>,
) -> Result<Arc<Cluster>> {
    let Prepared {
        section,
        identity,
        listeners,
    } = prepared;
    let store = Arc::clone(control.store());
    let role = starting_role(&store, section.role)?;
    let (role_tx, role_rx) = watch::channel(role);
    let peer = PeerClient::new(
        section.peer.node.clone(),
        section.peer.address,
        identity.client_config()?,
    )
    .context("invalid peer name")?;
    let cluster = Arc::new(Cluster {
        node: section.node.clone(),
        peer,
        peer_address: section.peer.address.to_string(),
        role: role_tx,
        config_role: section.role,
        store: Arc::clone(&store),
        peer_state: Mutex::new(PeerState::default()),
        sync: Mutex::new(SyncStatus {
            last_contact: None,
            last_copy: None,
            error: None,
        }),
        api: OnceLock::new(),
    });
    let shared = Arc::new(Shared {
        node: section.node.clone(),
        role: role_rx.clone(),
        store,
        log: Arc::clone(log),
        started_at,
    });
    let forward = Router::new()
        .route(API_PATH, post(run_forwarded))
        .layer(DefaultBodyLimit::max(MAX_FORWARD))
        .with_state(Arc::clone(&cluster));
    let serving = Serving {
        name: "cluster",
        router: server::router(shared).merge(forward),
        tls: Some(identity.server_config(&section.peer.node)?),
        max_connections: MAX_CONNECTIONS,
    };
    let until = crate::until(stopped.clone());
    tokio::spawn(async move {
        if let Err(err) = serve_router(listeners, serving, until).await {
            error!(%err, "the cluster listener failed");
        }
    });
    tokio::spawn(heartbeat(Arc::clone(&cluster), stopped.clone()));
    tokio::spawn(follow(
        Arc::clone(&cluster),
        Arc::clone(control),
        role_rx,
        stopped.clone(),
    ));
    info!(
        node = %section.node,
        role = %role,
        peer = %section.peer.node,
        peer_address = %section.peer.address,
        "cluster member"
    );
    Ok(cluster)
}

/// The role to start with: the one last set with promote or demote,
/// unless the config file's role changed since, which then wins.
fn starting_role(store: &Store, configured: Role) -> Result<Role> {
    let parse = |value: Option<String>| match value.as_deref() {
        Some("primary") => Some(Role::Primary),
        Some("replica") => Some(Role::Replica),
        _ => None,
    };
    let changed = parse(store.meta(ROLE_KEY)?);
    let base = parse(store.meta(ROLE_BASE_KEY)?);
    Ok(match (changed, base) {
        (Some(role), Some(base)) if base == configured => {
            if role != configured {
                info!(
                    role = %role,
                    config_file = %configured,
                    "starting with the role set by promote or demote"
                );
            }
            role
        }
        _ => configured,
    })
}

impl Cluster {
    /// Hands over the API, to run forwarded changes with.
    pub fn set_api(&self, api: Arc<Api>) {
        let _ = self.api.set(api);
    }

    fn role(&self) -> Role {
        *self.role.borrow()
    }

    fn peer_state(&self) -> PeerState {
        self.peer_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The other node's role, if it answered the last check.
    fn peer_role(&self) -> Option<Role> {
        self.peer_state().info.map(|info| info.role)
    }

    /// The cluster as the API reports it.
    pub fn status(&self) -> ClusterStatus {
        let role = self.role();
        let peer = self.peer_state();
        let sync = self
            .sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut problems = Vec::new();
        if let Some(info) = &peer.info {
            if info.role == role {
                problems.push(match role {
                    Role::Primary => String::from(
                        "both nodes are primary: demote one (POST /api/v1/cluster/demote on it) \
                         so its changes are not lost when the other's configuration replaces them"
                    ),
                    Role::Replica => String::from(
                        "both nodes are replicas: promote one (POST /api/v1/cluster/promote on it); \
                         until then the configuration cannot change"
                    ),
                });
            }
            if info.version != env!("CARGO_PKG_VERSION") {
                problems.push(format!(
                    "{} runs goethite {}, this node {}: run the same version on both",
                    info.node,
                    info.version,
                    env!("CARGO_PKG_VERSION")
                ));
            }
        }
        if role == Role::Replica
            && let Some(error) = &sync.error
        {
            problems.push(format!("cannot copy the primary's configuration: {error}"));
        }
        ClusterStatus {
            node: self.node.to_string(),
            role: api_role(role),
            config: self.store.version(),
            writable: matches!(self.writes(), Writes::Local | Writes::Forward),
            peer: PeerStatus {
                node: self.peer.peer().to_string(),
                address: self.peer_address.clone(),
                reachable: peer.info.is_some(),
                checked_at: peer.checked_at,
                role: peer.info.as_ref().map(|info| api_role(info.role)),
                version: peer.info.as_ref().map(|info| info.version.clone()),
                config: peer.info.as_ref().map(|info| info.config),
                error: peer.error,
            },
            sync: (role == Role::Replica).then_some(sync),
            problems,
        }
    }

    /// Where configuration changes made through this node go.
    pub fn writes(&self) -> Writes {
        let peer = self.peer_state();
        // Before the first check, try: forwarding says itself if it fails.
        if self.role() == Role::Replica && peer.checked_at.is_none() {
            return Writes::Forward;
        }
        match (self.role(), peer.info.map(|info| info.role)) {
            (Role::Primary, _) => Writes::Local,
            (Role::Replica, Some(Role::Primary)) => Writes::Forward,
            (Role::Replica, Some(Role::Replica)) => Writes::ReadOnly(format!(
                "this node is a replica and so is {}: promote one of them to change the \
                 configuration",
                self.peer.peer()
            )),
            (Role::Replica, None) => Writes::ReadOnly(format!(
                "the configuration can only change on the primary {}, which this node cannot \
                 reach; until it is back (or this node is promoted) it is read-only here",
                self.peer.peer()
            )),
        }
    }

    /// Sends a configuration change to the primary.
    pub async fn forward(&self, forwarded: Forwarded) -> Result<ForwardedAnswer, ApiError> {
        self.peer
            .post(API_PATH, &forwarded)
            .await
            .map_err(|err| match err {
                ClientError::Peer { status: 409, .. } => ApiError::unavailable(format!(
                    "{} is no longer the primary: {err}",
                    self.peer.peer()
                )),
                other => ApiError::unavailable(format!(
                    "cannot forward the change to the primary: {other}"
                )),
            })
    }

    /// The other node's statistics, unless it was unreachable at the last
    /// check (no point waiting for it).
    pub async fn peer_stats(&self, hours: u32) -> Result<StatsReport, ApiError> {
        if self.peer_state().info.is_none() && self.peer_state().checked_at.is_some() {
            return Err(ApiError::unavailable(format!(
                "{} is unreachable",
                self.peer.peer()
            )));
        }
        self.peer
            .stats(hours)
            .await
            .map_err(|err| ApiError::unavailable(err.to_string()))
    }

    /// Makes this node the primary or a replica.
    pub async fn set_role(
        &self,
        role: ClusterRole,
        force: bool,
        actor: Actor,
    ) -> Result<ClusterStatus, ApiError> {
        let role = match role {
            ClusterRole::Primary => Role::Primary,
            ClusterRole::Replica => Role::Replica,
        };
        if role == self.role() {
            return Ok(self.status());
        }
        // Look at the other node now, not as last checked.
        self.check_peer().await;
        let peer_role = self.peer_role();
        let peer = self.peer.peer();
        match role {
            Role::Primary if peer_role == Some(Role::Primary) && !force => {
                return Err(ApiError::conflict(format!(
                    "{peer} is reachable and is the primary: demote it first, or promote this \
                     node with force"
                )));
            }
            Role::Replica if peer_role != Some(Role::Primary) && !force => {
                return Err(ApiError::conflict(format!(
                    "{peer} is not a reachable primary, so this node would have nothing to \
                     follow: promote {peer} first, or demote this node with force"
                )));
            }
            _ => {}
        }
        let store = Arc::clone(&self.store);
        let config_role = self.config_role;
        let changed = tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
            store.set_meta(ROLE_KEY, &role.to_string())?;
            store.set_meta(ROLE_BASE_KEY, &config_role.to_string())?;
            match role {
                Role::Primary => store.start_epoch(&actor).map(drop)?,
                Role::Replica => store.record(
                    &actor,
                    AuditAction::Demote,
                    Some("this node is now a replica of the cluster's primary".into()),
                )?,
            }
            Ok(())
        })
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
        changed?;
        self.role.send_replace(role);
        info!(role = %role, peer = %peer, forced = force, "this node changed its role");
        Ok(self.status())
    }

    /// Asks the other node how it is, and remembers.
    async fn check_peer(&self) {
        let answer = self.peer.node().await;
        let mut state = self
            .peer_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.checked_at = Some(Timestamp::now());
        match answer {
            Ok(info) => {
                // The primary answering is contact, as a copy would be.
                if info.role == Role::Primary && self.role() == Role::Replica {
                    self.sync
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .last_contact = state.checked_at;
                }
                state.info = Some(info);
                state.error = None;
            }
            Err(err) => {
                state.info = None;
                state.error = Some(err.to_string());
            }
        }
    }

    fn record_sync(&self, attempt: &Result<bool, String>) {
        let now = Timestamp::now();
        let mut status = self.sync.lock().unwrap_or_else(PoisonError::into_inner);
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
}

fn api_role(role: Role) -> ClusterRole {
    match role {
        Role::Primary => ClusterRole::Primary,
        Role::Replica => ClusterRole::Replica,
    }
}

/// Checks on the other node every few seconds, for the status and for
/// knowing where configuration changes can go.
async fn heartbeat(cluster: Arc<Cluster>, stopped: watch::Receiver<bool>) {
    loop {
        cluster.check_peer().await;
        tokio::select! {
            () = tokio::time::sleep(HEARTBEAT) => {}
            () = crate::until(stopped.clone()) => return,
        }
    }
}

/// Runs a change the replica forwarded, if this node is the primary.
async fn run_forwarded(
    State(cluster): State<Arc<Cluster>>,
    Json(forwarded): Json<Forwarded>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;
    let refuse = |status: StatusCode, code: &str, message: String| {
        (
            status,
            Json(WireError {
                code: code.to_owned(),
                message,
            }),
        )
            .into_response()
    };
    if cluster.role() != Role::Primary {
        return refuse(
            StatusCode::CONFLICT,
            "not_primary",
            format!("{} is not the primary", cluster.node),
        );
    }
    let Some(api) = cluster.api.get() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "starting up".into(),
        );
    };
    match goethite_api::execute(api, cluster.peer.peer().as_str(), forwarded).await {
        Ok(answer) => Json(answer).into_response(),
        Err(err) => err.into_response(),
    }
}

/// While this node is a replica, copies every new configuration from the
/// primary. Failures are logged once each and retried with a growing pause.
async fn follow(
    cluster: Arc<Cluster>,
    control: Arc<Control>,
    mut role: watch::Receiver<Role>,
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
            result = copy_once(&cluster.peer, &control, have) => result,
            _ = role.changed() => continue,
            () = crate::until(stopped.clone()) => return,
        };
        cluster.record_sync(&attempt);
        match attempt {
            Ok(_) => {
                if last_error.take().is_some() {
                    info!(peer = %cluster.peer.peer(), "following the primary again");
                }
                backoff = FIRST_BACKOFF;
            }
            Err(err) => {
                if last_error.as_deref() != Some(&err) {
                    warn!(
                        peer = %cluster.peer.peer(),
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

/// Asks the primary for a configuration newer than `have` and applies it.
/// Returns whether one was copied.
async fn copy_once(
    peer: &PeerClient,
    control: &Arc<Control>,
    have: ConfigVersion,
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
