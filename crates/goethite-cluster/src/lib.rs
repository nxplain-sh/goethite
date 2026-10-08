//! Clustering and high availability for goethite.
//!
//! Two nodes form a cluster: the **primary** owns the configuration and the
//! **replica** copies it ([`PeerClient::config`], [`goethite_store::Store::replace`]).
//! They talk over a channel with mutual TLS ([`Identity`]): each node has a
//! certificate from the cluster's private CA ([`certs`]) that names it, and
//! each checks that the other is the configured peer.
//!
//! Losing the cluster layer never stops a node from answering DNS on its
//! own: a replica that cannot reach the primary keeps its last copy.
//!
//! Separately, [`vrrp`] moves a floating IP to whichever node is healthy.

pub mod certs;
mod client;
mod node;
pub mod server;
mod tls;
pub mod vrrp;
pub mod wire;

pub use client::{ClientError, PeerClient};
pub use node::{NodeId, NodeIdError, Role};
pub use tls::{Identity, TlsError};
