//! This node's part in a cluster: Raft ([`goethite_cluster::raft`]), the
//! listener the other members talk to, forwarding configuration changes to
//! the leader, keeping the cluster's members in line with the config file,
//! putting applied changes into effect, and the cluster's status.
//!
//! None of it is in the DNS path. A member without a leader keeps answering
//! with the configuration it has, and says so in its log and its status.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Extension, Json, Router};
use goethite_api::{
    Api, ApiError, ApiListeners, ClusterRole, ClusterStatus, Forwarded, ForwardedAnswer,
    MemberState, MemberStats, MemberStatus, Membership, PeerCertificate, PeerStatus, Serving,
    SyncStatus, Writes, serve_router,
};
use goethite_cluster::raft::node::RaftNode;
use goethite_cluster::raft::{Metrics, RaftId, matched_of, members_of, raft_id, state_of};
use goethite_cluster::server::{self, Shared};
use goethite_cluster::wire::{API_PATH, NodeInfo, RaftState, WireError};
use goethite_cluster::{ClientError, Identity, NodeId, PeerClient, Peers, Role};
use goethite_store::{Actor, AuditAction, ConfigVersion, QueryLog, StatsReport, Store};
use jiff::Timestamp;
use rustls::ClientConfig;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::config::ClusterSection;
use crate::control::Control;
use crate::secrets::ClusterPem;

/// Cluster connections served at once: each member needs a few.
const MAX_CONNECTIONS: usize = 32;

/// How often each node checks on the other members, and the leader on the
/// cluster's membership.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// The largest forwarded change: an API body and its envelope.
const MAX_FORWARD: usize = 2 * 1024 * 1024;

/// How many entries behind the leader a learner may be and still become a
/// voter.
const CAUGHT_UP: u64 = 16;

/// How long a configuration change may take to be put into effect before
/// the API answers anyway.
const SETTLE: Duration = Duration::from_secs(60);

/// The store's `meta` key set when this node left its cluster: it then
/// waits to be added to another, rather than starting one.
const LEFT_KEY: &str = "left_cluster";

/// The store's `meta` keys of goethite 0.4's role, set by promote or
/// demote, and of the config file's role then.
const ROLE_KEY: &str = "cluster_role";
const ROLE_BASE_KEY: &str = "cluster_role_base";

/// This goethite's version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Another member, as last checked.
#[derive(Clone, Debug, Default)]
struct Check {
    checked_at: Option<Timestamp>,
    info: Option<NodeInfo>,
    error: Option<String>,
}

/// This node's cluster, running.
pub(crate) struct Cluster {
    node: NodeId,
    section: ClusterSection,
    raft: Arc<RaftNode>,
    tls: Arc<ClientConfig>,
    peers: Peers,
    store: Arc<Store>,
    checks: Mutex<BTreeMap<NodeId, Check>>,
    /// Why starting the cluster failed, if it did.
    start_error: Mutex<Option<String>>,
    /// The configuration version queries use.
    effective: watch::Receiver<ConfigVersion>,
    /// When the configuration last changed here.
    last_change: Mutex<Option<Timestamp>>,
    /// The leader last seen, to log changes.
    last_leader: Mutex<Option<NodeId>>,
    /// The API, to run changes forwarded by the other members; set once it
    /// exists, cleared when the control plane stops (it refers back here).
    api: Mutex<Option<Arc<Api>>>,
}

/// What the cluster needs from the rest of the control plane.
pub(crate) struct Parts<'a> {
    /// The control plane.
    pub control: &'a Arc<Control>,
    /// The query log, for the statistics.
    pub log: &'a Arc<QueryLog>,
    /// When this node started.
    pub started_at: Timestamp,
}

/// Starts Raft, the cluster listener on `listeners`, the checks on the
/// other members and putting applied changes into effect, in `tasks`,
/// until `stopped` turns true.
///
/// # Errors
///
/// If the certificates do not fit together, or Raft cannot start.
pub(crate) async fn start(
    section: &ClusterSection,
    pem: &ClusterPem,
    listeners: ApiListeners,
    parts: &Parts<'_>,
    tasks: &mut JoinSet<()>,
    stopped: &watch::Receiver<bool>,
) -> Result<Arc<Cluster>> {
    let Parts {
        control,
        log,
        started_at,
    } = *parts;
    let identity = Identity::from_pem(
        section.node.clone(),
        pem.ca.as_bytes(),
        pem.node.cert.as_bytes(),
        pem.node.key.as_bytes(),
    )?;
    let tls = identity.client_config()?;
    let store = Arc::clone(control.store());
    let raft = RaftNode::start(
        section.node.clone(),
        section.listen,
        false,
        Arc::clone(&store),
        Arc::clone(&tls),
    )
    .await
    .context("cannot start Raft")?;
    let (effective_tx, effective_rx) = watch::channel(store.version());
    let cluster = Arc::new(Cluster {
        node: section.node.clone(),
        section: section.clone(),
        raft: Arc::clone(&raft),
        tls,
        peers: Peers::default(),
        store: Arc::clone(&store),
        checks: Mutex::new(BTreeMap::new()),
        start_error: Mutex::new(None),
        effective: effective_rx,
        last_change: Mutex::new(None),
        last_leader: Mutex::new(None),
        api: Mutex::new(None),
    });
    cluster.update_peers();
    let shared = Arc::new(Shared {
        node: section.node.clone(),
        witness: false,
        raft: Arc::clone(raft.shared()),
        store,
        log: Some(Arc::clone(log)),
        started_at,
    });
    let forward = Router::new()
        .route(API_PATH, post(run_forwarded))
        .layer(DefaultBodyLimit::max(MAX_FORWARD))
        .with_state(Arc::clone(&cluster));
    let serving = Serving {
        name: "cluster",
        router: server::router(shared).merge(forward),
        tls: Some(identity.server_config(cluster.peers.clone())?),
        max_connections: MAX_CONNECTIONS,
    };
    let until = crate::until(stopped.clone());
    tasks.spawn(async move {
        if let Err(err) = serve_router(listeners, serving, until).await {
            error!(%err, "the cluster listener failed");
        }
    });
    tasks.spawn(upkeep(Arc::clone(&cluster), stopped.clone()));
    tasks.spawn(react(
        Arc::clone(&cluster),
        Arc::clone(control),
        effective_tx,
        stopped.clone(),
    ));
    info!(
        node = %section.node,
        listen = %section.listen,
        members = %section.members().map(|m| m.node.as_str()).collect::<Vec<_>>().join(", "),
        "cluster member"
    );
    Ok(cluster)
}

impl Cluster {
    /// Hands over the API, to run forwarded changes with.
    pub(crate) fn set_api(&self, api: Arc<Api>) {
        *self.api.lock().unwrap_or_else(PoisonError::into_inner) = Some(api);
    }

    /// Lets go of the API: the control plane is stopping, and the API
    /// refers back to this cluster.
    pub(crate) fn release_api(&self) {
        *self.api.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Stops Raft, so it lets go of the store.
    pub(crate) async fn shutdown(&self) {
        self.raft.shutdown().await;
    }

    fn checks(&self) -> BTreeMap<NodeId, Check> {
        self.checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn metrics(&self) -> Option<Metrics> {
        self.raft.metrics()
    }

    /// Whether this node leads the cluster.
    fn leads(&self) -> bool {
        self.metrics().is_some_and(|metrics| {
            metrics.running_state.is_ok() && state_of(Some(&metrics)).0 == RaftState::Leader
        })
    }

    /// The other members to check: those in the config file, at the
    /// addresses it gives, and the rest of the cluster's.
    fn targets(&self) -> BTreeMap<NodeId, SocketAddr> {
        let mut targets = BTreeMap::new();
        if let Some(metrics) = self.metrics() {
            for recorded in members_of(&metrics) {
                if let (Ok(node), Ok(address)) =
                    (recorded.member.node(), recorded.member.address.parse())
                    && node != self.node
                {
                    targets.insert(node, address);
                }
            }
        }
        for member in self.section.members() {
            targets.insert(member.node.clone(), member.address);
        }
        targets
    }

    /// Lets the members in the config file and in the cluster connect.
    fn update_peers(&self) {
        let mut nodes: BTreeSet<NodeId> = self.targets().into_keys().collect();
        nodes.insert(self.node.clone());
        self.peers.set(nodes);
    }

    /// Starts the cluster on this node, if the config file says so and the
    /// node is in none, never left one, and no member that answered is in
    /// one already: a node that lost its store waits to be added back
    /// rather than start a second cluster.
    async fn start_if_asked(&self) {
        if self.raft.cluster().is_some() {
            return;
        }
        let joined = self.checks().into_iter().find_map(|(node, check)| {
            check
                .info
                .and_then(|info| info.cluster)
                .map(|cluster| (node, cluster))
        });
        let store = Arc::clone(&self.store);
        let stored = tokio::task::spawn_blocking(move || {
            let role = |key| {
                store
                    .meta(key)
                    .ok()
                    .flatten()
                    .and_then(|value| match value.as_str() {
                        "primary" => Some(Role::Primary),
                        "replica" => Some(Role::Replica),
                        _ => None,
                    })
            };
            let left = store.meta(LEFT_KEY).ok().flatten().is_some();
            (role(ROLE_KEY), role(ROLE_BASE_KEY), left)
        })
        .await;
        let Ok((role, base, left)) = stored else {
            return;
        };
        if left || !self.section.bootstraps(role, base) {
            info!("waiting for the cluster's leader to add this node");
            return;
        }
        if let Some((member, cluster)) = joined {
            warn!(
                %member,
                cluster = %format!("{cluster:016x}"),
                "not starting a cluster: a member is in one already; waiting for its leader to \
                 add this node"
            );
            return;
        }
        match self.raft.bootstrap().await {
            Ok(()) => info!(
                node = %self.node,
                "started the cluster: this node's configuration is the cluster's"
            ),
            Err(err) => {
                error!(%err, "cannot start the cluster");
                *self
                    .start_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(err.to_string());
            }
        }
    }

    /// Asks every other member how it is, at once, and remembers. Members
    /// becoming unreachable or reachable again are logged.
    async fn check_members(&self) {
        let mut asking = JoinSet::new();
        for (node, address) in self.targets() {
            let tls = Arc::clone(&self.tls);
            asking.spawn(async move {
                let answer = match PeerClient::new(node.clone(), address, tls) {
                    Ok(client) => client.node().await.map_err(|err| err.to_string()),
                    Err(err) => Err(err.to_string()),
                };
                (node, answer)
            });
        }
        let mut checks = BTreeMap::new();
        while let Some(joined) = asking.join_next().await {
            let Ok((node, answer)) = joined else {
                continue;
            };
            let checked_at = Some(Timestamp::now());
            checks.insert(
                node,
                match answer {
                    Ok(info) => Check {
                        checked_at,
                        info: Some(info),
                        error: None,
                    },
                    Err(error) => Check {
                        checked_at,
                        info: None,
                        error: Some(error),
                    },
                },
            );
        }
        let previous = std::mem::replace(
            &mut *self.checks.lock().unwrap_or_else(PoisonError::into_inner),
            checks.clone(),
        );
        for (node, check) in &checks {
            let was = previous.get(node).map(|check| check.info.is_some());
            match (&check.error, was) {
                (Some(error), Some(true) | None) => warn!(member = %node, "unreachable: {error}"),
                (None, Some(false)) => info!(member = %node, "reachable again"),
                _ => {}
            }
        }
    }

    /// Logs a change of leader.
    fn log_leader(&self) {
        let (_, term, leader) = state_of(self.metrics().as_ref());
        let mut last = self
            .last_leader
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *last == leader {
            return;
        }
        match &leader {
            Some(leader) if *leader == self.node => info!(term, "this node leads the cluster"),
            Some(leader) => info!(%leader, term, "the cluster's leader"),
            None if self.raft.cluster().is_some() => warn!("the cluster has no leader"),
            None => {}
        }
        last.clone_from(&leader);
    }

    /// As the leader: adds the members in the config file that answer and
    /// are in no other cluster, follows them to new addresses, and makes
    /// every member that has caught up a voter, once that makes three
    /// voters or more. Two voters would be worse than one: losing either
    /// would stop all changes.
    async fn tend(&self) {
        let Some(metrics) = self.metrics() else {
            return;
        };
        let recorded: BTreeMap<RaftId, String> = members_of(&metrics)
            .into_iter()
            .map(|recorded| (recorded.id, recorded.member.address))
            .collect();
        let ours = self.raft.cluster();
        let checks = self.checks();
        for member in self.section.members() {
            let Some(info) = checks
                .get(&member.node)
                .and_then(|check| check.info.as_ref())
            else {
                continue;
            };
            if info.version != VERSION {
                continue;
            }
            let address = member.address.to_string();
            match recorded.get(&raft_id(&member.node)) {
                None if info.cluster.is_none() || info.cluster == ours => {
                    match self.raft.add_learner(&member.node, member.address).await {
                        Ok(()) => info!(member = %member.node, "added to the cluster"),
                        Err(err) => {
                            warn!(member = %member.node, %err, "cannot add it to the cluster");
                        }
                    }
                }
                Some(known) if *known != address && info.cluster == ours => {
                    match self.raft.set_address(&member.node, member.address).await {
                        Ok(()) => info!(member = %member.node, %address, "moved"),
                        Err(err) => {
                            warn!(member = %member.node, %err, "cannot record its new address");
                        }
                    }
                }
                _ => {}
            }
        }
        let Some(metrics) = self.metrics() else {
            return;
        };
        let last = metrics.last_log_index.unwrap_or(0);
        let members = members_of(&metrics);
        let voters: BTreeSet<RaftId> = members.iter().filter(|m| m.voter).map(|m| m.id).collect();
        let wanted: BTreeSet<RaftId> = members
            .iter()
            .filter(|m| {
                m.voter
                    || matched_of(&metrics, m.id)
                        .is_some_and(|matched| matched.saturating_add(CAUGHT_UP) >= last)
            })
            .map(|m| m.id)
            .collect();
        if wanted.len() >= 3 && wanted != voters {
            let names: Vec<&str> = members
                .iter()
                .filter(|m| wanted.contains(&m.id))
                .map(|m| m.member.name.as_str())
                .collect();
            match self.raft.set_voters(wanted).await {
                Ok(()) => info!(voters = %names.join(", "), "the cluster's voters"),
                Err(err) => warn!(%err, "cannot change the cluster's voters"),
            }
        }
    }

    /// Why configuration changes cannot be made through this node now, if
    /// they cannot.
    fn blocker(&self) -> Option<String> {
        let Some(metrics) = self.metrics() else {
            return Some("Raft is not running on this node".into());
        };
        if let Err(fatal) = &metrics.running_state {
            return Some(format!(
                "Raft stopped on this node ({fatal}); restart goethite"
            ));
        }
        if self.raft.cluster().is_none() {
            return Some(
                "this node is in no cluster yet, so its configuration cannot change: the \
                 cluster's leader adds it once it is in the leader's [[cluster.member]] (or set \
                 bootstrap = true on the node that starts the cluster)"
                    .into(),
            );
        }
        let Some(leader) = metrics.current_leader else {
            return Some(
                "the cluster has no leader right now, so its configuration cannot change: most \
                 of its voters must reach each other to elect one"
                    .into(),
            );
        };
        if leader == self.raft.id() {
            if let Some((node, version)) = self.other_version() {
                return Some(format!(
                    "{node} runs goethite {version}, this node {VERSION}: finish upgrading every \
                     member before changing the configuration"
                ));
            }
            return None;
        }
        // A learner keeps the last leader it heard of: is it still there?
        let name = members_of(&metrics)
            .into_iter()
            .find(|recorded| recorded.id == leader)
            .and_then(|recorded| recorded.member.node().ok());
        if let Some(name) = name
            && self
                .checks()
                .get(&name)
                .is_some_and(|check| check.info.is_none())
        {
            return Some(format!(
                "the cluster's leader, {name}, does not answer, so the configuration cannot \
                 change through this node; if it is gone for good and the cluster cannot elect \
                 another, take the cluster over (POST /api/v1/cluster/promote)"
            ));
        }
        None
    }

    /// A member that runs another goethite version, if one does.
    fn other_version(&self) -> Option<(NodeId, String)> {
        self.checks().into_iter().find_map(|(node, check)| {
            check
                .info
                .filter(|info| info.version != VERSION)
                .map(|info| (node, info.version))
        })
    }

    /// Where configuration changes made through this node go.
    pub(crate) fn writes(&self) -> Writes {
        match self.blocker() {
            Some(reason) => Writes::ReadOnly(reason),
            None if self.leads() => Writes::Local,
            None => Writes::Forward,
        }
    }

    /// The leader and the address to reach it at: the config file's, if it
    /// lists it.
    fn leader_address(&self) -> Option<(NodeId, SocketAddr)> {
        let metrics = self.metrics()?;
        let leader = metrics.current_leader?;
        let recorded = members_of(&metrics)
            .into_iter()
            .find(|recorded| recorded.id == leader)?;
        let node = recorded.member.node().ok()?;
        let address = self
            .section
            .members()
            .find(|member| member.node == node)
            .map(|member| member.address)
            .or_else(|| recorded.member.address.parse().ok())?;
        Some((node, address))
    }

    /// Sends a configuration change to the leader.
    pub(crate) async fn forward(&self, forwarded: Forwarded) -> Result<ForwardedAnswer, ApiError> {
        let (leader, address) = self
            .leader_address()
            .ok_or_else(|| ApiError::unavailable("the cluster has no leader right now"))?;
        let client = PeerClient::new(leader.clone(), address, Arc::clone(&self.tls))
            .map_err(|err| ApiError::internal(err.to_string()))?;
        client
            .post(API_PATH, &forwarded)
            .await
            .map_err(|err| match err {
                ClientError::Peer { status: 409, .. } => ApiError::unavailable(format!(
                    "{leader} no longer leads the cluster; make the change again"
                )),
                ClientError::Peer {
                    status: 503,
                    message,
                    ..
                } => ApiError::unavailable(message),
                other => ApiError::unavailable(format!(
                    "cannot forward the change to the leader: {other}"
                )),
            })
    }

    /// Resolves once queries use the configuration as it is now, or after
    /// [`SETTLE`].
    pub(crate) async fn settled(&self) {
        let target = self.store.version();
        let mut effective = self.effective.clone();
        let _ = tokio::time::timeout(SETTLE, async {
            let _ = effective
                .wait_for(|have| !target.replaces(*have))
                .await
                .is_ok();
        })
        .await;
    }

    /// The other members' statistics; those unreachable at the last check
    /// are not waited for, and witnesses have none.
    pub(crate) async fn member_stats(&self, hours: u32) -> Vec<MemberStats> {
        let checks = self.checks();
        let mut asking = JoinSet::new();
        let mut stats = Vec::new();
        for (node, address) in self.targets() {
            let check = checks.get(&node);
            if check
                .and_then(|check| check.info.as_ref())
                .is_some_and(|info| info.witness)
            {
                continue;
            }
            if check.is_some_and(|check| check.info.is_none()) {
                stats.push(MemberStats {
                    node: node.to_string(),
                    stats: Err("unreachable".into()),
                });
                continue;
            }
            let tls = Arc::clone(&self.tls);
            asking.spawn(async move {
                let answer: Result<StatsReport, String> =
                    match PeerClient::new(node.clone(), address, tls) {
                        Ok(client) => client.stats(hours).await.map_err(|err| err.to_string()),
                        Err(err) => Err(err.to_string()),
                    };
                MemberStats {
                    node: node.to_string(),
                    stats: answer,
                }
            });
        }
        while let Some(joined) = asking.join_next().await {
            if let Ok(answer) = joined {
                stats.push(answer);
            }
        }
        stats
    }

    /// The cluster as the API reports it.
    pub(crate) fn status(&self) -> ClusterStatus {
        let metrics = self.metrics();
        let (state, term, leader) = state_of(metrics.as_ref());
        let recorded: BTreeMap<RaftId, bool> = metrics
            .as_ref()
            .map(|metrics| {
                members_of(metrics)
                    .into_iter()
                    .map(|recorded| (recorded.id, recorded.voter))
                    .collect()
            })
            .unwrap_or_default();
        let checks = self.checks();
        let membership = |id: RaftId| match recorded.get(&id) {
            Some(true) => Membership::Voter,
            Some(false) => Membership::Learner,
            None => Membership::Configured,
        };
        let mut members = vec![MemberStatus {
            node: self.node.to_string(),
            address: self.section.listen.to_string(),
            this_node: true,
            membership: membership(self.raft.id()),
            witness: false,
            reachable: true,
            checked_at: None,
            state: Some(member_state(state)),
            version: Some(VERSION.to_owned()),
            config: Some(self.store.version()),
            matched: None,
            error: None,
        }];
        for (node, address) in self.targets() {
            let id = raft_id(&node);
            let check = checks.get(&node).cloned().unwrap_or_default();
            let info = check.info.as_ref();
            members.push(MemberStatus {
                node: node.to_string(),
                address: address.to_string(),
                this_node: false,
                membership: membership(id),
                witness: info.is_some_and(|info| info.witness),
                reachable: info.is_some(),
                checked_at: check.checked_at,
                state: info.map(|info| member_state(info.state)),
                version: info.map(|info| info.version.clone()),
                config: info.map(|info| info.config),
                matched: metrics.as_ref().and_then(|metrics| matched_of(metrics, id)),
                error: check.error.clone(),
            });
        }
        let blocker = self.blocker();
        let problems = self.problems(&members, blocker.as_deref(), &recorded);
        let peer = peer_status(&members, leader.as_ref());
        let leads = state == RaftState::Leader;
        ClusterStatus {
            node: self.node.to_string(),
            role: if leads {
                ClusterRole::Primary
            } else {
                ClusterRole::Replica
            },
            state: member_state(state),
            cluster: self.raft.cluster().map(|id| format!("{id:016x}")),
            leader: leader.map(|leader| leader.to_string()),
            term,
            config: self.store.version(),
            writable: blocker.is_none(),
            members,
            peer,
            sync: (!leads).then(|| SyncStatus {
                last_contact: self.raft.shared().heard(),
                last_copy: *self
                    .last_change
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
                error: blocker.clone(),
            }),
            problems,
        }
    }

    /// What someone should look at, in words.
    fn problems(
        &self,
        members: &[MemberStatus],
        blocker: Option<&str>,
        recorded: &BTreeMap<RaftId, bool>,
    ) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(err) = self
            .start_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            problems.push(format!("cannot start the cluster: {err}"));
        }
        if let Some(blocker) = blocker {
            problems.push(blocker.to_owned());
        }
        let ours = self.raft.cluster();
        let checks = self.checks();
        for member in members.iter().filter(|member| !member.this_node) {
            let info = NodeId::new(member.node.as_str())
                .ok()
                .and_then(|node| checks.get(&node).cloned())
                .and_then(|check| check.info);
            match info {
                Some(info) => {
                    if let Some(theirs) = info.cluster
                        && ours.is_some_and(|ours| ours != theirs)
                    {
                        problems.push(format!(
                            "{} is in another cluster, {theirs:016x}: to have it join this one, \
                             demote it (POST /api/v1/cluster/demote on {})",
                            member.node, member.node
                        ));
                    }
                    if info.version != VERSION {
                        problems.push(format!(
                            "{} runs goethite {}, this node {VERSION}: run the same version on \
                             every member",
                            member.node, info.version
                        ));
                    }
                }
                None if member.membership != Membership::Learner => problems.push(format!(
                    "{} is unreachable: {}",
                    member.node,
                    member.error.as_deref().unwrap_or("not checked yet")
                )),
                None => {}
            }
        }
        if recorded.values().filter(|voter| **voter).count() == 2 {
            problems.push(
                "the cluster has two voters, so losing either stops configuration changes: add \
                 a witness"
                    .into(),
            );
        }
        problems
    }

    /// Takes the cluster over (`Primary`), or leaves it to join another
    /// (`Replica`).
    pub(crate) async fn set_role(
        &self,
        role: ClusterRole,
        force: bool,
        actor: Actor,
    ) -> Result<ClusterStatus, ApiError> {
        match role {
            ClusterRole::Primary => self.take_over(force, actor).await,
            ClusterRole::Replica => self.rejoin(force, actor).await,
        }
    }

    /// A leader of this node's cluster that answered the last check, if
    /// there is one. Raft's own idea is no proof: a learner never stands
    /// for election, so it keeps the last leader it heard of.
    fn reachable_leader(&self) -> Option<NodeId> {
        if self.leads() {
            return Some(self.node.clone());
        }
        let ours = self.raft.cluster();
        self.checks().into_iter().find_map(|(node, check)| {
            check
                .info
                .filter(|info| info.state == RaftState::Leader && info.cluster == ours)
                .map(|_| node)
        })
    }

    async fn take_over(&self, force: bool, actor: Actor) -> Result<ClusterStatus, ApiError> {
        if self.leads() {
            return Ok(self.status());
        }
        self.check_members().await;
        if !force && let Some(leader) = self.reachable_leader() {
            return Err(ApiError::conflict(format!(
                "{leader} leads the cluster and is reachable, so there is nothing to take over; \
                 to take over anyway, leaving two clusters until the other members are demoted, \
                 pass force"
            )));
        }
        self.raft
            .take_over()
            .await
            .map_err(|err| ApiError::unavailable(format!("cannot take the cluster over: {err}")))?;
        self.audit(
            actor,
            AuditAction::Promote,
            "this node took the cluster over: it is the only voter of a new cluster, with its \
             configuration",
        )
        .await;
        warn!(
            forced = force,
            "this node took the cluster over: demote the other members so they join it"
        );
        self.update_peers();
        Ok(self.status())
    }

    async fn rejoin(&self, force: bool, actor: Actor) -> Result<ClusterStatus, ApiError> {
        self.check_members().await;
        let ours = self.raft.cluster();
        let other = self.checks().into_iter().find_map(|(node, check)| {
            check
                .info
                .filter(|info| {
                    info.state == RaftState::Leader
                        && info.cluster.is_some()
                        && info.cluster != ours
                })
                .map(|_| node)
        });
        if other.is_none() {
            if ours.is_none() {
                return Ok(self.status());
            }
            if !force {
                return Err(ApiError::conflict(
                    "no leader of another cluster is reachable, so this node would have nothing \
                     to join: it stays in its cluster; to leave anyway, pass force",
                ));
            }
        }
        self.raft
            .leave()
            .await
            .map_err(|err| ApiError::unavailable(format!("cannot leave the cluster: {err}")))?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.set_meta(LEFT_KEY, "true"))
            .await
            .map_err(|err| ApiError::internal(err.to_string()))??;
        let detail = match &other {
            Some(leader) => format!("this node left its cluster, to join {leader}'s"),
            None => "this node left its cluster".to_owned(),
        };
        self.audit(actor, AuditAction::Demote, &detail).await;
        info!(leader = ?other.map(|node| node.to_string()), "left the cluster: its leader adds this node to its own");
        Ok(self.status())
    }

    /// Removes a member from the cluster, as its leader.
    pub(crate) async fn remove_member(
        &self,
        node: String,
        actor: Actor,
    ) -> Result<ClusterStatus, ApiError> {
        let node = NodeId::new(node).map_err(|err| ApiError::bad_request(err.to_string()))?;
        if !self.leads() {
            return Err(ApiError::unavailable(
                "this node does not lead the cluster; make the change again",
            ));
        }
        if node == self.node {
            return Err(ApiError::conflict(format!(
                "{node} leads the cluster: stop it, and remove it through the next leader"
            )));
        }
        if self.section.members().any(|member| member.node == node) {
            return Err(ApiError::conflict(format!(
                "{node} is in this node's config file ([[cluster.member]]): remove it there and \
                 restart goethite first, or it is added again"
            )));
        }
        let id = raft_id(&node);
        let metrics = self
            .metrics()
            .ok_or_else(|| ApiError::unavailable("Raft is not running on this node"))?;
        if !members_of(&metrics)
            .iter()
            .any(|recorded| recorded.id == id)
        {
            return Err(ApiError::not_found(format!("{node} is not a member")));
        }
        self.raft
            .remove(id)
            .await
            .map_err(|err| ApiError::unavailable(err.to_string()))?;
        // Two voters would be worse than one.
        if let Some(metrics) = self.metrics() {
            let voters = members_of(&metrics).iter().filter(|m| m.voter).count();
            if voters == 2
                && let Err(err) = self.raft.set_voters(BTreeSet::from([self.raft.id()])).await
            {
                warn!(%err, "cannot go back to one voter");
            }
        }
        self.audit(
            actor,
            AuditAction::Delete,
            &format!("removed {node} from the cluster"),
        )
        .await;
        info!(member = %node, "removed from the cluster");
        self.update_peers();
        Ok(self.status())
    }

    /// Records a cluster action in this node's audit log.
    async fn audit(&self, actor: Actor, action: AuditAction, detail: &str) {
        let store = Arc::clone(&self.store);
        let detail = detail.to_owned();
        let recorded =
            tokio::task::spawn_blocking(move || store.record(&actor, action, Some(detail))).await;
        if !matches!(recorded, Ok(Ok(()))) {
            warn!("cannot record the cluster change in the audit log");
        }
    }
}

/// The API's name for a Raft state.
fn member_state(state: RaftState) -> MemberState {
    match state {
        RaftState::Leader => MemberState::Leader,
        RaftState::Follower => MemberState::Follower,
        RaftState::Candidate => MemberState::Candidate,
        RaftState::Learner => MemberState::Learner,
        RaftState::Stopped => MemberState::Stopped,
        RaftState::Unknown => MemberState::Unknown,
    }
}

/// goethite 0.4's one other node: the leader, or on the leader another
/// member, the first by name.
fn peer_status(members: &[MemberStatus], leader: Option<&NodeId>) -> PeerStatus {
    let others = || members.iter().filter(|member| !member.this_node);
    let chosen = leader
        .and_then(|leader| others().find(|member| member.node == leader.as_str()))
        .or_else(|| others().next());
    match chosen {
        Some(member) => PeerStatus {
            node: member.node.clone(),
            address: member.address.clone(),
            reachable: member.reachable,
            checked_at: member.checked_at,
            role: member.state.map(|state| {
                if state == MemberState::Leader {
                    ClusterRole::Primary
                } else {
                    ClusterRole::Replica
                }
            }),
            version: member.version.clone(),
            config: member.config,
            error: member.error.clone(),
        },
        None => PeerStatus {
            node: String::new(),
            address: String::new(),
            reachable: false,
            checked_at: None,
            role: None,
            version: None,
            config: None,
            error: Some("the cluster has no other member".into()),
        },
    }
}

/// Starts the cluster if asked, then checks on the other members every few
/// seconds and, on the leader, tends the membership.
async fn upkeep(cluster: Arc<Cluster>, stopped: watch::Receiver<bool>) {
    cluster.check_members().await;
    cluster.start_if_asked().await;
    loop {
        cluster.check_members().await;
        cluster.update_peers();
        if cluster.leads() {
            cluster.tend().await;
        }
        cluster.log_leader();
        tokio::select! {
            () = tokio::time::sleep(CHECK_EVERY) => {}
            () = crate::until(stopped.clone()) => return,
        }
    }
}

/// Puts every configuration change into effect, whether it was made here
/// or came through the cluster's log: the filter is rebuilt when lists or
/// rules changed (and lists downloaded when lists did), the policy
/// otherwise. `effective` follows the version in effect.
async fn react(
    cluster: Arc<Cluster>,
    control: Arc<Control>,
    effective: watch::Sender<ConfigVersion>,
    stopped: watch::Receiver<bool>,
) {
    let store = Arc::clone(control.store());
    let mut versions = store.subscribe();
    let mut last = store.config();
    loop {
        tokio::select! {
            changed = versions.changed() => if changed.is_err() { return },
            () = crate::until(stopped.clone()) => return,
        }
        let version = *versions.borrow_and_update();
        let config = store.config();
        let lists_changed = config.lists != last.lists;
        if lists_changed || config.rules != last.rules {
            control.rebuild_filter().await;
        } else {
            control.rebuild_policy();
        }
        if lists_changed {
            control.refresh_lists();
        }
        last = config;
        *cluster
            .last_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Timestamp::now());
        effective.send_replace(version);
    }
}

/// Runs a change another member forwarded, if this node leads.
async fn run_forwarded(
    State(cluster): State<Arc<Cluster>>,
    certificate: Option<Extension<PeerCertificate>>,
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
    let Some(from) = certificate.and_then(|Extension(cert)| cluster.peers.name_of(&cert.0)) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "unknown_member",
            "the change comes from no known member".into(),
        );
    };
    match cluster.writes() {
        Writes::Local => {}
        Writes::Forward => {
            return refuse(
                StatusCode::CONFLICT,
                "not_leader",
                format!("{} does not lead the cluster", cluster.node),
            );
        }
        Writes::ReadOnly(reason) => {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "unavailable", reason);
        }
    }
    let api = cluster
        .api
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(api) = api else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "starting up".into(),
        );
    };
    match goethite_api::execute(&api, from.as_str(), forwarded).await {
        Ok(answer) => Json(answer).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `goethite cluster init`: creates the cluster's CA in `dir`.
///
/// # Errors
///
/// If a file exists already or cannot be written.
pub(crate) fn init(dir: &Path) -> Result<String> {
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
pub(crate) fn cert(dir: &Path, node: &str, force: bool) -> Result<String> {
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
