//! What nodes send each other over the cluster channel.
//!
//! The channel is HTTP/1.1 inside mutual TLS, with JSON bodies, under
//! `/cluster/v1/`. Both nodes run the same goethite version (the
//! configuration schema is checked on every copy), so these types can
//! change between releases; they are not a public API.

use goethite_store::ConfigVersion;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::node::{NodeId, Role};

/// The path of [`NodeInfo`].
pub const NODE_PATH: &str = "/cluster/v1/node";

/// The path of the configuration a replica follows.
pub const CONFIG_PATH: &str = "/cluster/v1/config";

/// The longest a configuration request waits for a change, in seconds.
pub const MAX_WAIT_SECS: u64 = 55;

/// About a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Its name.
    pub node: NodeId,
    /// Its role.
    pub role: Role,
    /// Its goethite version.
    pub version: String,
    /// When it started.
    pub started_at: Timestamp,
    /// Its configuration's version.
    pub config: ConfigVersion,
}

/// The query of a configuration request: the version the replica has, and
/// how long to wait for a newer one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigQuery {
    /// The replica's epoch.
    #[serde(default)]
    pub epoch: u64,
    /// The replica's version.
    #[serde(default)]
    pub version: u64,
    /// Seconds to wait for a change, at most [`MAX_WAIT_SECS`].
    #[serde(default)]
    pub wait: u64,
}

impl ConfigQuery {
    /// The query for a replica at `have`, waiting `wait` seconds.
    pub fn new(have: ConfigVersion, wait: u64) -> Self {
        Self {
            epoch: have.epoch,
            version: have.version,
            wait,
        }
    }

    /// The version the replica has.
    pub fn have(self) -> ConfigVersion {
        ConfigVersion {
            epoch: self.epoch,
            version: self.version,
        }
    }

    /// The query string.
    pub fn to_query_string(self) -> String {
        format!(
            "epoch={}&version={}&wait={}",
            self.epoch, self.version, self.wait
        )
    }
}

/// An error answer on the cluster channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// A stable code, such as `not_primary`.
    pub code: String,
    /// For people.
    pub message: String,
}
