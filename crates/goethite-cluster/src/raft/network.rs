//! Raft's messages to the other members, over the cluster channel: each a
//! JSON `POST` with the cluster's ID ([`RaftRequest`]), answered with
//! openraft's result as JSON. A member that cannot be reached is
//! [`Unreachable`], so openraft backs off from it.

#![allow(
    clippy::result_large_err,
    reason = "openraft's RPCError is large, and its traits return it"
)]
#![allow(
    clippy::unused_async_trait_impl,
    reason = "openraft's traits are async; some answers are at hand"
)]

use std::sync::Arc;

use openraft::AnyError;
use openraft::error::{
    InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use rustls::ClientConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{ClusterTag, Member, RaftId, TypeConfig};
use crate::client::{ClientError, PeerClient};
use crate::wire::{APPEND_PATH, RaftRequest, SNAPSHOT_PATH, VOTE_PATH};

/// Makes [`Connection`]s to members.
#[derive(Clone)]
pub struct Network {
    tls: Arc<ClientConfig>,
    tag: ClusterTag,
}

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Network {
    /// Connections with this node's [`crate::Identity::client_config`],
    /// tagged with its cluster.
    pub fn new(tls: Arc<ClientConfig>, tag: ClusterTag) -> Self {
        Self { tls, tag }
    }
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Connection;

    async fn new_client(&mut self, target: RaftId, node: &Member) -> Self::Network {
        Connection {
            target,
            member: node.clone(),
            client: PeerClient::for_member(node, Arc::clone(&self.tls)),
            tag: self.tag.clone(),
        }
    }
}

/// Raft's way to one member.
pub struct Connection {
    target: RaftId,
    member: Member,
    client: Result<PeerClient, String>,
    tag: ClusterTag,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

impl Connection {
    #[tracing::instrument(level = "debug", name = "raft.call", skip_all, fields(%path, target = self.target))]
    async fn call<Req, Resp, E>(
        &self,
        path: &str,
        rpc: Req,
        option: &RPCOption,
    ) -> Result<Resp, RPCError<RaftId, Member, RaftError<RaftId, E>>>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let unreachable =
            |reason: &str| RPCError::Unreachable(Unreachable::new(&AnyError::error(reason)));
        let client = self.client.as_ref().map_err(|reason| unreachable(reason))?;
        let cluster = self
            .tag
            .get()
            .ok_or_else(|| unreachable("this node is not in a cluster"))?;
        let request = RaftRequest { cluster, rpc };
        let answer: Result<Resp, RaftError<RaftId, E>> = client
            .post_within(path, &request, option.hard_ttl())
            .await
            .map_err(|err| match err {
                ClientError::Connect { .. } | ClientError::Peer { .. } => {
                    RPCError::Unreachable(Unreachable::new(&err))
                }
                ClientError::Decode { .. } => RPCError::Network(NetworkError::new(&err)),
            })?;
        answer.map_err(|err| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.member.clone(),
                err,
            ))
        })
    }
}

impl RaftNetwork<TypeConfig> for Connection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<RaftId>, RPCError<RaftId, Member, RaftError<RaftId>>> {
        self.call(APPEND_PATH, rpc, &option).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<RaftId>,
        RPCError<RaftId, Member, RaftError<RaftId, InstallSnapshotError>>,
    > {
        self.call(SNAPSHOT_PATH, rpc, &option).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<RaftId>,
        option: RPCOption,
    ) -> Result<VoteResponse<RaftId>, RPCError<RaftId, Member, RaftError<RaftId>>> {
        self.call(VOTE_PATH, rpc, &option).await
    }
}
