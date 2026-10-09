//! This node's Raft, and what it can do with the cluster: start one, take
//! one over, leave one, and (as the leader) change who is in it.
//!
//! Raft runs whenever the node is in a cluster or waiting to be added to
//! one. Taking over and leaving replace it: they shut it down, forget the
//! log, and start it afresh, keeping the configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use goethite_store::{Applied, Command, Replicator, Store, StoreError};
use openraft::error::{ClientWriteError, RaftError};
use openraft::{ChangeMembers, ServerState};
use rustls::ClientConfig;
use tokio::runtime::Handle;
use tracing::info;

use super::network::Network;
use super::routes::{RaftCell, RaftShared};
use super::storage::{LogStore, StateMachine};
use super::{ClusterTag, Member, Metrics, Raft, RaftId, config, raft_id};
use crate::node::NodeId;

/// How long a configuration change may take to be agreed on and applied.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a new cluster's first node may take to lead it.
const LEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a cluster operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RaftNodeError {
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Raft is not running on this node.
    #[error("Raft is not running on this node")]
    NotRunning,
    /// Raft refused or failed.
    #[error("{0}")]
    Raft(String),
}

/// This node's Raft.
pub struct RaftNode {
    name: NodeId,
    id: RaftId,
    address: SocketAddr,
    witness: bool,
    store: Arc<Store>,
    network: Network,
    shared: Arc<RaftShared>,
    /// Serializes starting a cluster, taking one over and leaving one.
    changing: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for RaftNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftNode")
            .field("name", &self.name)
            .field("witness", &self.witness)
            .finish_non_exhaustive()
    }
}

impl RaftNode {
    /// Starts Raft for the node `name`, which the others reach at
    /// `address`, on `store`, connecting with `tls`. From then on, changes
    /// to `store` go through Raft. A `witness` votes and never leads.
    ///
    /// # Errors
    ///
    /// If the store's cluster state cannot be read, or Raft cannot start.
    pub async fn start(
        name: NodeId,
        address: SocketAddr,
        witness: bool,
        store: Arc<Store>,
        tls: Arc<ClientConfig>,
    ) -> Result<Arc<Self>, RaftNodeError> {
        let tag = ClusterTag::load(Arc::clone(&store))?;
        let shared = Arc::new(RaftShared {
            raft: RaftCell::default(),
            tag: tag.clone(),
            heard: Mutex::new(None),
        });
        let node = Arc::new(Self {
            id: raft_id(&name),
            name,
            address,
            witness,
            store: Arc::clone(&store),
            network: Network::new(tls, tag),
            shared,
            changing: tokio::sync::Mutex::new(()),
        });
        node.launch().await?;
        store.set_replicator(Arc::new(RaftReplicator {
            raft: node.shared.raft.clone(),
            runtime: Handle::current(),
        }));
        Ok(node)
    }

    /// Starts a Raft on the store as it is, and puts it in place.
    async fn launch(&self) -> Result<Raft, RaftNodeError> {
        let config = config(self.witness).map_err(|err| RaftNodeError::Raft(err.to_string()))?;
        let machine = StateMachine::new(Arc::clone(&self.store), &self.name)?;
        let raft = Raft::new(
            self.id,
            config,
            self.network.clone(),
            LogStore::new(Arc::clone(&self.store)),
            machine,
        )
        .await
        .map_err(|err| RaftNodeError::Raft(err.to_string()))?;
        self.shared.raft.set(Some(raft.clone()));
        Ok(raft)
    }

    /// This node's name.
    pub fn name(&self) -> &NodeId {
        &self.name
    }

    /// This node's Raft number.
    pub fn id(&self) -> RaftId {
        self.id
    }

    /// Whether this node is a witness.
    pub fn witness(&self) -> bool {
        self.witness
    }

    /// What the cluster listener's Raft routes need.
    pub fn shared(&self) -> &Arc<RaftShared> {
        &self.shared
    }

    /// The cluster this node is in, if any.
    pub fn cluster(&self) -> Option<u64> {
        self.shared.tag.get()
    }

    /// The Raft, if it runs.
    pub fn raft(&self) -> Option<Raft> {
        self.shared.raft.get()
    }

    fn running(&self) -> Result<Raft, RaftNodeError> {
        self.raft().ok_or(RaftNodeError::NotRunning)
    }

    /// Raft's metrics, if it runs.
    pub fn metrics(&self) -> Option<Metrics> {
        self.raft().map(|raft| raft.metrics().borrow().clone())
    }

    /// Starts a new cluster with this node as its only voter and leader,
    /// and its configuration as the cluster's.
    ///
    /// # Errors
    ///
    /// If this node is in a cluster already, or Raft fails.
    pub async fn bootstrap(&self) -> Result<(), RaftNodeError> {
        let _changing = self.changing.lock().await;
        self.start_cluster().await
    }

    async fn start_cluster(&self) -> Result<(), RaftNodeError> {
        let raft = self.running()?;
        if self.cluster().is_some() {
            return Err(RaftNodeError::Raft(
                "this node is in a cluster already".into(),
            ));
        }
        self.shared.tag.start()?;
        let members = BTreeMap::from([(self.id, Member::new(&self.name, self.address))]);
        raft.initialize(members)
            .await
            .map_err(|err| RaftNodeError::Raft(err.to_string()))?;
        raft.wait(Some(LEAD_TIMEOUT))
            .state(ServerState::Leader, "lead the new cluster")
            .await
            .map_err(|err| RaftNodeError::Raft(err.to_string()))?;
        let seed = self.store.seed(self.name.as_str());
        raft.client_write(seed)
            .await
            .map_err(|err| RaftNodeError::Raft(err.to_string()))?;
        info!(node = %self.name, "started a new cluster with this node's configuration");
        Ok(())
    }

    /// Leaves the cluster, keeping the configuration: Raft starts again in
    /// no cluster, until a leader adds this node to its own.
    ///
    /// # Errors
    ///
    /// If the store cannot forget the cluster, or Raft cannot start again.
    pub async fn leave(&self) -> Result<(), RaftNodeError> {
        let _changing = self.changing.lock().await;
        self.forget().await
    }

    async fn forget(&self) -> Result<(), RaftNodeError> {
        if let Some(raft) = self.shared.raft.set(None) {
            let _ = raft.shutdown().await;
        }
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.leave_cluster())
            .await
            .map_err(|err| RaftNodeError::Raft(err.to_string()))??;
        self.shared.tag.forget();
        self.launch().await?;
        Ok(())
    }

    /// Takes the cluster over: leaves it, and starts a new one with this
    /// node as its only voter and its configuration as the cluster's. For
    /// when the cluster cannot elect a leader and will not again soon.
    ///
    /// # Errors
    ///
    /// If leaving or starting fails.
    pub async fn take_over(&self) -> Result<(), RaftNodeError> {
        let _changing = self.changing.lock().await;
        self.forget().await?;
        self.start_cluster().await
    }

    /// Adds `name` at `address` as a learner: it receives the log, and
    /// votes once [`RaftNode::set_voters`] makes it a voter.
    ///
    /// # Errors
    ///
    /// If this node does not lead, or Raft fails.
    pub async fn add_learner(
        &self,
        name: &NodeId,
        address: SocketAddr,
    ) -> Result<(), RaftNodeError> {
        self.running()?
            .add_learner(raft_id(name), Member::new(name, address), false)
            .await
            .map(drop)
            .map_err(|err| RaftNodeError::Raft(err.to_string()))
    }

    /// Records that the member `name` is now at `address`.
    ///
    /// # Errors
    ///
    /// If this node does not lead, or Raft fails.
    pub async fn set_address(
        &self,
        name: &NodeId,
        address: SocketAddr,
    ) -> Result<(), RaftNodeError> {
        let nodes = BTreeMap::from([(raft_id(name), Member::new(name, address))]);
        self.change(ChangeMembers::SetNodes(nodes), false).await
    }

    /// Makes `voters` the cluster's voters. Voters left out stay as
    /// learners.
    ///
    /// # Errors
    ///
    /// If this node does not lead, a voter is not a member yet, or Raft
    /// fails.
    pub async fn set_voters(&self, voters: BTreeSet<RaftId>) -> Result<(), RaftNodeError> {
        self.change(ChangeMembers::ReplaceAllVoters(voters), true)
            .await
    }

    /// Removes the member `id` from the cluster, voter or learner.
    ///
    /// # Errors
    ///
    /// If this node does not lead, or Raft fails.
    pub async fn remove(&self, id: RaftId) -> Result<(), RaftNodeError> {
        let voter = self
            .metrics()
            .is_some_and(|metrics| metrics.membership_config.voter_ids().any(|v| v == id));
        let ids = BTreeSet::from([id]);
        if voter {
            self.change(ChangeMembers::RemoveVoters(ids), false).await
        } else {
            self.change(ChangeMembers::RemoveNodes(ids), false).await
        }
    }

    async fn change(
        &self,
        change: ChangeMembers<RaftId, Member>,
        retain: bool,
    ) -> Result<(), RaftNodeError> {
        self.running()?
            .change_membership(change, retain)
            .await
            .map(drop)
            .map_err(|err| RaftNodeError::Raft(err.to_string()))
    }

    /// Stops Raft; changes to the store are written at once again.
    pub async fn shutdown(&self) {
        self.store.clear_replicator();
        if let Some(raft) = self.shared.raft.set(None) {
            let _ = raft.shutdown().await;
        }
    }
}

/// Puts the store's changes through Raft.
struct RaftReplicator {
    raft: RaftCell,
    runtime: Handle,
}

impl Replicator for RaftReplicator {
    fn replicate(&self, command: Command) -> Result<Applied, StoreError> {
        let raft = self
            .raft
            .get()
            .ok_or_else(|| StoreError::Unavailable("Raft is not running on this node".into()))?;
        let joined = raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .next()
            .is_some();
        if !joined {
            return Err(StoreError::Unavailable(
                "this node is in no cluster yet, so its configuration cannot change: it takes \
                 the cluster's once a leader adds it"
                    .into(),
            ));
        }
        let write = async { tokio::time::timeout(WRITE_TIMEOUT, raft.client_write(command)).await };
        // A blocking thread may wait on the runtime; a worker thread must
        // say so first.
        let written = tokio::task::block_in_place(|| self.runtime.block_on(write));
        match written {
            Ok(Ok(response)) => Ok(response.data),
            Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_)))) => {
                Err(StoreError::Unavailable(
                    "this node no longer leads the cluster; make the change again".into(),
                ))
            }
            Ok(Err(err)) => Err(StoreError::Unavailable(format!(
                "the cluster cannot take the change: {err}"
            ))),
            Err(_) => Err(StoreError::Unavailable(format!(
                "the cluster did not confirm the change within {} seconds: are most of its \
                 voters reachable? The change may still be made",
                WRITE_TIMEOUT.as_secs()
            ))),
        }
    }
}
