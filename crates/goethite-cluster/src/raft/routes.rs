//! What a member answers Raft's messages with, on the cluster listener.
//!
//! Only members with a certificate from the cluster's CA reach these routes
//! ([`crate::Identity::server_config`]). Each message must also carry this
//! node's cluster ID ([`ClusterTag`]); a node in no cluster yet joins the
//! cluster of the first leader that sends it entries.

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use jiff::Timestamp;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};

use super::{ClusterTag, Raft, RaftId, TagError, TypeConfig};
use crate::wire::{APPEND_PATH, RaftRequest, SNAPSHOT_PATH, VOTE_PATH, WireError};

/// The largest Raft message: entries can hold a whole configuration (when a
/// cluster starts), and a configuration with a million custom rules is about
/// 60 MB.
pub const MAX_MESSAGE: usize = 256 * 1024 * 1024;

/// The largest snapshot received, all its pieces together.
pub const MAX_SNAPSHOT: u64 = 512 * 1024 * 1024;

/// This node's Raft, which it replaces when it takes a cluster over or
/// leaves one; `None` while there is none.
#[derive(Clone, Default)]
pub struct RaftCell(Arc<RwLock<Option<Raft>>>);

impl std::fmt::Debug for RaftCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftCell")
            .field("running", &self.get().is_some())
            .finish()
    }
}

impl RaftCell {
    /// The Raft, if there is one.
    pub fn get(&self) -> Option<Raft> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Puts `raft` in place, returning the one it replaces.
    pub fn set(&self, raft: Option<Raft>) -> Option<Raft> {
        std::mem::replace(
            &mut *self.0.write().unwrap_or_else(PoisonError::into_inner),
            raft,
        )
    }
}

/// What the Raft routes need.
#[derive(Debug)]
pub struct RaftShared {
    /// This node's Raft.
    pub raft: RaftCell,
    /// Its cluster.
    pub tag: ClusterTag,
    /// When a leader last sent entries (or a heartbeat).
    pub heard: Mutex<Option<Timestamp>>,
}

impl RaftShared {
    /// Raft, ready for a message from cluster `cluster`; with `join`, a
    /// node in no cluster yet joins it.
    #[allow(clippy::result_large_err, reason = "the error is the response itself")]
    fn accept(&self, cluster: u64, join: bool) -> Result<Raft, Response> {
        let raft = self.raft.get().ok_or_else(|| {
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Raft is not running on this node".into(),
            )
        })?;
        self.tag.check(cluster, join).map_err(|err| {
            let code = match err {
                TagError::Other { .. } => "other_cluster",
                TagError::NotJoined => "not_joined",
                TagError::Store(_) => "unavailable",
            };
            refuse(StatusCode::CONFLICT, code, err.to_string())
        })?;
        Ok(raft)
    }

    /// When a leader was last heard from.
    pub fn heard(&self) -> Option<Timestamp> {
        *self.heard.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The Raft routes.
pub fn router(shared: Arc<RaftShared>) -> Router {
    Router::new()
        .route(APPEND_PATH, post(append))
        .route(VOTE_PATH, post(vote))
        .route(SNAPSHOT_PATH, post(snapshot))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE))
        .with_state(shared)
}

#[tracing::instrument(level = "debug", name = "raft.append", skip_all)]
async fn append(
    State(shared): State<Arc<RaftShared>>,
    Json(request): Json<RaftRequest<AppendEntriesRequest<TypeConfig>>>,
) -> Response {
    let raft = match shared.accept(request.cluster, true) {
        Ok(raft) => raft,
        Err(response) => return response,
    };
    let answer = raft.append_entries(request.rpc).await;
    if answer.is_ok() {
        *shared.heard.lock().unwrap_or_else(PoisonError::into_inner) = Some(Timestamp::now());
    }
    Json(answer).into_response()
}

#[tracing::instrument(level = "debug", name = "raft.vote", skip_all)]
async fn vote(
    State(shared): State<Arc<RaftShared>>,
    Json(request): Json<RaftRequest<VoteRequest<RaftId>>>,
) -> Response {
    match shared.accept(request.cluster, false) {
        Ok(raft) => Json(raft.vote(request.rpc).await).into_response(),
        Err(response) => response,
    }
}

#[tracing::instrument(level = "debug", name = "raft.snapshot", skip_all)]
async fn snapshot(
    State(shared): State<Arc<RaftShared>>,
    Json(request): Json<RaftRequest<InstallSnapshotRequest<TypeConfig>>>,
) -> Response {
    let size = u64::try_from(request.rpc.data.len()).unwrap_or(u64::MAX);
    if request.rpc.offset.saturating_add(size) > MAX_SNAPSHOT {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            format!("snapshots larger than {MAX_SNAPSHOT} bytes are refused"),
        );
    }
    match shared.accept(request.cluster, true) {
        Ok(raft) => Json(raft.install_snapshot(request.rpc).await).into_response(),
        Err(response) => response,
    }
}

fn refuse(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(WireError {
            code: code.to_owned(),
            message,
        }),
    )
        .into_response()
}
