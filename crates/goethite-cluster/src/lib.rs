//! Clustering and high availability for goethite.
//!
//! Replicates configuration between nodes over mutually authenticated TLS,
//! manages a VRRP floating IP and, later, consensus via Raft. Losing the cluster
//! layer must never stop a node from answering DNS on its own.
//!
//! Status: empty skeleton. Two-node config sync and VRRP arrive in Phase 3.
