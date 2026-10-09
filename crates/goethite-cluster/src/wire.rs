//! What nodes send each other over the cluster channel.
//!
//! The channel is HTTP/1.1 inside mutual TLS, with JSON bodies, under
//! `/cluster/v1/`. Every node runs the same goethite version, so these types
//! can change between releases; they are not a public API. New fields get
//! defaults, so a node can still tell which version its peer runs.

use goethite_store::ConfigVersion;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::node::NodeId;

/// The path of [`NodeInfo`].
pub const NODE_PATH: &str = "/cluster/v1/node";

/// The path of a node's statistics, for the cluster's.
pub const STATS_PATH: &str = "/cluster/v1/stats";

/// The path of Raft's append-entries messages.
pub const APPEND_PATH: &str = "/cluster/v1/raft/append";

/// The path of Raft's vote requests.
pub const VOTE_PATH: &str = "/cluster/v1/raft/vote";

/// The path of Raft's snapshot pieces.
pub const SNAPSHOT_PATH: &str = "/cluster/v1/raft/snapshot";

/// The path a member asks the leader to remove it from the cluster on.
pub const LEAVE_PATH: &str = "/cluster/v1/leave";

/// The query of a statistics request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsQuery {
    /// The last this many hours.
    #[serde(default)]
    pub hours: u32,
}

/// The path configuration changes are forwarded to the leader on; the
/// binary serves it, since it runs them through the API.
pub const API_PATH: &str = "/cluster/v1/api";

/// What a node does in Raft right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaftState {
    /// It leads: configuration changes are made through it.
    Leader,
    /// It follows the leader and votes.
    Follower,
    /// It stands for election.
    Candidate,
    /// It follows the leader but does not vote, or is not in a cluster yet.
    Learner,
    /// Raft stopped on it.
    Stopped,
    /// A state this version does not know.
    #[default]
    #[serde(other)]
    Unknown,
}

/// About a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Its name.
    pub node: NodeId,
    /// Its goethite version.
    pub version: String,
    /// When it started.
    pub started_at: Timestamp,
    /// Its configuration's version.
    pub config: ConfigVersion,
    /// The cluster it is in, if any.
    #[serde(default)]
    pub cluster: Option<u64>,
    /// Whether it is a witness: it votes, and never leads.
    #[serde(default)]
    pub witness: bool,
    /// What it does in Raft.
    #[serde(default)]
    pub state: RaftState,
    /// Its Raft term.
    #[serde(default)]
    pub term: u64,
    /// The leader, as far as it knows.
    #[serde(default)]
    pub leader: Option<NodeId>,
}

/// A Raft message, with the cluster it belongs to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaftRequest<T> {
    /// The cluster's ID ([`crate::raft::ClusterTag`]).
    pub cluster: u64,
    /// The message.
    pub rpc: T,
}

/// A member's request to the leader to leave the cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveRequest {
    /// The cluster's ID.
    pub cluster: u64,
    /// The member.
    pub node: NodeId,
}

/// An error answer on the cluster channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// A stable code, such as `not_leader`.
    pub code: String,
    /// For people.
    pub message: String,
}
