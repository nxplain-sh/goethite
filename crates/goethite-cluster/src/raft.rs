//! Raft, through openraft: the cluster's members agree on one log of
//! configuration changes, and every node applies it to its store in the
//! same order ([`goethite_store::Store::apply`]).
//!
//! The log and this node's vote live in the store's database, beside the
//! configuration they build ([`storage`]). Members talk over the cluster
//! channel ([`network`], [`routes`]). A witness votes but never stands for
//! election, so two goethite nodes and a small witness survive the loss of
//! any one of them.

use std::fmt;
// declare_raft_types! names it for snapshots.
use std::io::Cursor;
use std::sync::{Arc, Mutex, PoisonError};

use goethite_store::{Applied, Command, Store, StoreError};
use serde::{Deserialize, Serialize};

use crate::node::{NodeId, NodeIdError};
use crate::wire::RaftState;

pub mod network;
pub mod node;
pub mod routes;
pub mod storage;

openraft::declare_raft_types!(
    /// The cluster's Raft types: store commands in, their outcomes out.
    pub TypeConfig:
        D = Command,
        R = Applied,
        Node = Member,
);

/// The cluster's Raft.
pub type Raft = openraft::Raft<TypeConfig>;

/// A member's number in Raft: [`raft_id`] of its name.
pub type RaftId = u64;

/// Raft's metrics of this node.
pub type Metrics = openraft::RaftMetrics<RaftId, Member>;

/// A member's membership of the cluster, as Raft records it.
pub type Membership = openraft::StoredMembership<RaftId, Member>;

/// How often the leader tells the others it is there, in milliseconds.
pub const HEARTBEAT_MS: u64 = 500;

/// The shortest silence after which a follower stands for election.
const ELECTION_MIN_MS: u64 = 1_500;

/// The longest.
const ELECTION_MAX_MS: u64 = 3_000;

/// Entries since the last snapshot that make Raft take another.
const SNAPSHOT_EVERY: u64 = 500;

/// Entries kept after a snapshot, for members only a little behind.
const KEEP_AFTER_SNAPSHOT: u64 = 100;

/// Entries sent at once.
const MAX_PAYLOAD_ENTRIES: u64 = 64;

/// The size of the pieces a snapshot is sent in.
pub const SNAPSHOT_CHUNK: u64 = 1024 * 1024;

/// A member of the cluster, as Raft records it: its name and its cluster
/// address. Both come from the configuration of the leader that added it,
/// so they are checked again when used.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Its name, as in its certificate.
    pub name: String,
    /// Its cluster listener, such as `192.0.2.12:8054`.
    pub address: String,
}

impl Member {
    /// The member `name` at `address`.
    pub fn new(name: &NodeId, address: std::net::SocketAddr) -> Self {
        Self {
            name: name.to_string(),
            address: address.to_string(),
        }
    }

    /// Its name, checked.
    ///
    /// # Errors
    ///
    /// [`NodeIdError`] for a name that is not a node name.
    pub fn node(&self) -> Result<NodeId, NodeIdError> {
        NodeId::new(self.name.clone())
    }
}

impl fmt::Display for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.name, self.address)
    }
}

/// The Raft number of the member named `node`: FNV-1a of the name, so every
/// node computes the same one without asking. Configurations are checked
/// for two names with the same number ([`raft_id`] collisions are
/// astronomically unlikely, but refused all the same).
pub fn raft_id(node: &NodeId) -> RaftId {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in node.as_str().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Raft's settings. Timings suit a LAN with room to spare: a leader that
/// falls silent is replaced within about 3 seconds. A `witness` votes but
/// never stands for election.
///
/// # Errors
///
/// openraft's, if the settings do not fit together (they do).
#[allow(clippy::result_large_err, reason = "openraft's ConfigError")]
pub fn config(witness: bool) -> Result<Arc<openraft::Config>, openraft::ConfigError> {
    let config = openraft::Config {
        cluster_name: "goethite".into(),
        heartbeat_interval: HEARTBEAT_MS,
        election_timeout_min: ELECTION_MIN_MS,
        election_timeout_max: ELECTION_MAX_MS,
        max_payload_entries: MAX_PAYLOAD_ENTRIES,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(SNAPSHOT_EVERY),
        max_in_snapshot_log_to_keep: KEEP_AFTER_SNAPSHOT,
        snapshot_max_chunk_size: SNAPSHOT_CHUNK,
        enable_elect: !witness,
        ..openraft::Config::default()
    };
    config.validate().map(Arc::new)
}

/// What `metrics` say this node does: its state, its term and the leader
/// it knows of. No metrics means no Raft.
pub fn state_of(metrics: Option<&Metrics>) -> (RaftState, u64, Option<NodeId>) {
    let Some(metrics) = metrics else {
        return (RaftState::Stopped, 0, None);
    };
    let state = if metrics.running_state.is_err() {
        RaftState::Stopped
    } else {
        match metrics.state {
            openraft::ServerState::Leader => RaftState::Leader,
            openraft::ServerState::Follower => RaftState::Follower,
            openraft::ServerState::Candidate => RaftState::Candidate,
            openraft::ServerState::Learner => RaftState::Learner,
            openraft::ServerState::Shutdown => RaftState::Stopped,
        }
    };
    let leader = metrics
        .current_leader
        .and_then(|id| metrics.membership_config.membership().get_node(&id))
        .and_then(|member| member.node().ok());
    (state, metrics.current_term, leader)
}

/// A member as Raft records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// Its Raft number.
    pub id: RaftId,
    /// Its name and address.
    pub member: Member,
    /// Whether it votes.
    pub voter: bool,
}

/// The cluster's members, as `metrics` record them.
pub fn members_of(metrics: &Metrics) -> Vec<Recorded> {
    let membership = metrics.membership_config.membership();
    let voters: std::collections::BTreeSet<RaftId> = membership.voter_ids().collect();
    membership
        .nodes()
        .map(|(id, member)| Recorded {
            id: *id,
            member: member.clone(),
            voter: voters.contains(id),
        })
        .collect()
}

/// On the leader: the index of the last entry member `id` is known to hold.
pub fn matched_of(metrics: &Metrics, id: RaftId) -> Option<u64> {
    metrics
        .replication
        .as_ref()?
        .get(&id)?
        .as_ref()
        .map(|log_id| log_id.index)
}

/// The store key of the cluster's ID.
const CLUSTER_ID: &str = "id";

/// Which cluster this node is in: a random number chosen when a cluster
/// starts (or is taken over). Every Raft message carries it, and a node
/// refuses messages from another cluster, so the logs of two clusters
/// never mix. A node in no cluster yet takes the ID of the first leader
/// that sends it entries.
#[derive(Clone)]
pub struct ClusterTag {
    id: Arc<Mutex<Option<u64>>>,
    store: Arc<Store>,
}

impl fmt::Debug for ClusterTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterTag")
            .field("id", &self.get())
            .finish_non_exhaustive()
    }
}

/// Why a Raft message was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    /// It came from another cluster.
    #[error("this node is in cluster {ours:016x}, not {theirs:016x}")]
    Other {
        /// This node's cluster.
        ours: u64,
        /// The sender's.
        theirs: u64,
    },
    /// This node is in no cluster yet, so it cannot vote.
    #[error("this node has not joined a cluster yet")]
    NotJoined,
    /// The store failed.
    #[error("{0}")]
    Store(String),
}

impl ClusterTag {
    /// The cluster `store` is in, if any.
    ///
    /// # Errors
    ///
    /// A store error.
    pub fn load(store: Arc<Store>) -> Result<Self, StoreError> {
        let id = store
            .cluster_value(CLUSTER_ID)?
            .and_then(|text| u64::from_str_radix(&text, 16).ok());
        Ok(Self {
            id: Arc::new(Mutex::new(id)),
            store,
        })
    }

    /// The cluster's ID, if this node is in one.
    pub fn get(&self) -> Option<u64> {
        *self.id.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a new cluster: a new ID, kept in the store.
    ///
    /// # Errors
    ///
    /// A store error, or no randomness.
    pub fn start(&self) -> Result<u64, StoreError> {
        let mut bytes = [0_u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| StoreError::Unavailable("no randomness for a cluster ID".into()))?;
        let id = u64::from_be_bytes(bytes);
        self.set(Some(id))?;
        Ok(id)
    }

    /// Forgets the cluster, as [`Store::leave_cluster`] does in the store.
    pub fn forget(&self) {
        *self.id.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Checks a message from cluster `theirs`. With `join`, a node in no
    /// cluster yet joins that one.
    ///
    /// # Errors
    ///
    /// [`TagError`] saying why the message is refused.
    pub fn check(&self, theirs: u64, join: bool) -> Result<(), TagError> {
        match self.get() {
            Some(ours) if ours == theirs => Ok(()),
            Some(ours) => Err(TagError::Other { ours, theirs }),
            None if join => self
                .set(Some(theirs))
                .map_err(|err| TagError::Store(err.to_string())),
            None => Err(TagError::NotJoined),
        }
    }

    fn set(&self, id: Option<u64>) -> Result<(), StoreError> {
        let mut current = self.id.lock().unwrap_or_else(PoisonError::into_inner);
        let text = id.map(|id| format!("{id:016x}"));
        self.store.set_cluster_value(CLUSTER_ID, text.as_deref())?;
        *current = id;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_tags_keep_clusters_apart() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let tag = ClusterTag::load(Arc::clone(&store)).unwrap();
        assert_eq!(tag.get(), None);
        assert_eq!(tag.check(7, false), Err(TagError::NotJoined));
        tag.check(7, true).unwrap();
        assert_eq!(tag.get(), Some(7));
        assert_eq!(
            tag.check(8, true),
            Err(TagError::Other { ours: 7, theirs: 8 })
        );
        assert_eq!(ClusterTag::load(Arc::clone(&store)).unwrap().get(), Some(7));
        let started = tag.start().unwrap();
        assert_eq!(
            ClusterTag::load(Arc::clone(&store)).unwrap().get(),
            Some(started)
        );
        store.leave_cluster().unwrap();
        tag.forget();
        assert_eq!(ClusterTag::load(store).unwrap().get(), None);
    }

    #[test]
    fn raft_ids_are_stable() {
        let dns1 = NodeId::new("dns1").unwrap();
        assert_eq!(raft_id(&dns1), raft_id(&NodeId::new("dns1").unwrap()));
        assert_ne!(raft_id(&dns1), raft_id(&NodeId::new("dns2").unwrap()));
        // FNV-1a 64 of "dns1", fixed forever: it is in every log.
        assert_eq!(raft_id(&dns1), 0xe360_7467_6588_6737);
    }

    #[test]
    fn the_settings_fit() {
        let leader = config(false).unwrap();
        assert!(leader.enable_elect);
        assert!(!config(true).unwrap().enable_elect);
    }
}
