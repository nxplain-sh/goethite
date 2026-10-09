//! Who a node is: its name, and goethite 0.4's role.

use std::fmt;
use std::str::FromStr;

use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};

/// The domain under which node names appear in certificates. `.invalid`
/// never resolves (RFC 2606), so the names cannot collide with real ones.
const CERT_DOMAIN: &str = "node.goethite.invalid";

/// A node's name, such as `dns1`: 1 to 63 lowercase ASCII letters, digits
/// and hyphens, starting with a letter and not ending with a hyphen. It is
/// part of the node's certificate, so peers can check who they talk to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId(String);

/// A node name that breaks the rules.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "{0:?} is not a node name: use 1 to 63 lowercase letters, digits and hyphens, starting with a letter"
)]
pub struct NodeIdError(String);

impl NodeId {
    /// The name, checked.
    ///
    /// # Errors
    ///
    /// [`NodeIdError`] if it breaks the rules.
    pub fn new(name: impl Into<String>) -> Result<Self, NodeIdError> {
        let name = name.into();
        let bytes = name.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_lowercase)
            && bytes.last().is_some_and(|b| *b != b'-')
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if valid {
            Ok(Self(name))
        } else {
            Err(NodeIdError(name))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The DNS name in the node's certificate, such as
    /// `dns1.node.goethite.invalid`.
    pub fn cert_name(&self) -> String {
        format!("{}.{CERT_DOMAIN}", self.0)
    }

    /// The name to check the node's certificate against.
    ///
    /// # Errors
    ///
    /// Never for a valid node name; the error is rustls's.
    pub fn server_name(
        &self,
    ) -> Result<ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
        ServerName::try_from(self.cert_name())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NodeId {
    type Err = NodeIdError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::new(name)
    }
}

impl TryFrom<String> for NodeId {
    type Error = NodeIdError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl From<NodeId> for String {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

/// A node's role in goethite 0.4's two-node clusters, still read from
/// config files: the primary starts the Raft cluster, the replica waits to
/// be added to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Started the cluster, with its configuration.
    Primary,
    /// Joins the primary's cluster.
    Replica,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Primary => "primary",
            Self::Replica => "replica",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_names() {
        for good in ["dns1", "a", "dns-east-2", &"a".repeat(63)] {
            let id = NodeId::new(good).unwrap();
            assert_eq!(id.as_str(), good);
            assert!(id.server_name().is_ok());
        }
        for bad in [
            "",
            "1dns",
            "-dns",
            "dns-",
            "DNS1",
            "dns_1",
            "dns.1",
            "dñs",
            &"a".repeat(64),
        ] {
            assert!(NodeId::new(bad).is_err(), "{bad}");
        }
        assert_eq!(
            NodeId::new("dns1").unwrap().cert_name(),
            "dns1.node.goethite.invalid"
        );
        let parsed: NodeId = serde_json::from_str("\"dns2\"").unwrap();
        assert_eq!(parsed.as_str(), "dns2");
        assert!(serde_json::from_str::<NodeId>("\"Dns2\"").is_err());
    }
}
