//! Clustering and high availability for goethite.
//!
//! The members of a cluster agree on one log of configuration changes with
//! Raft ([`raft`]), and every member applies it to its own store. One
//! member leads: changes are made through it, and the others forward theirs
//! to it. A witness only votes, so two goethite nodes and a witness keep a
//! majority when any one of them is lost. Members talk over a channel with
//! mutual TLS ([`Identity`]): each has a certificate from the cluster's
//! private CA ([`certs`]) that names it, and accepts only members it knows
//! ([`Peers`]).
//!
//! Losing the cluster layer never stops a node from answering DNS on its
//! own: a member without a leader keeps the configuration it has.
//!
//! Separately, [`vrrp`] moves a floating IP to whichever node is healthy.

pub mod certs;
mod client;
mod node;
pub mod raft;
pub mod server;
mod tls;
pub mod vrrp;
pub mod wire;

pub use client::{ClientError, PeerClient};
pub use node::{NodeId, NodeIdError, Role};
pub use tls::{Identity, Peers, TlsError};
