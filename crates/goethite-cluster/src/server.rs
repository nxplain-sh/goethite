//! The cluster listener's routes: what a node answers the other members.
//!
//! The listener itself (TLS, connection limits) is the API server's, with
//! the mutual-TLS configuration from [`crate::Identity::server_config`], so
//! every request here comes from a member of the cluster.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use goethite_store::stats::TOP_FOR_MERGE;
use goethite_store::{QueryLog, Store};
use jiff::Timestamp;

use crate::node::NodeId;
use crate::raft::routes::{self, RaftShared};
use crate::raft::state_of;
use crate::wire::{NODE_PATH, NodeInfo, STATS_PATH, StatsQuery, WireError};

/// What the cluster routes need.
pub struct Shared {
    /// This node's name.
    pub node: NodeId,
    /// Whether it is a witness.
    pub witness: bool,
    /// Its Raft.
    pub raft: Arc<RaftShared>,
    /// The store.
    pub store: Arc<Store>,
    /// The query log, for the statistics; a witness has none.
    pub log: Option<Arc<QueryLog>>,
    /// When this node started.
    pub started_at: Timestamp,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("node", &self.node)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// This node, as the other members see it.
    pub fn info(&self) -> NodeInfo {
        let metrics = self
            .raft
            .raft
            .get()
            .map(|raft| raft.metrics().borrow().clone());
        let (state, term, leader) = state_of(metrics.as_ref());
        NodeInfo {
            node: self.node.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at: self.started_at,
            config: self.store.version(),
            cluster: self.raft.tag.get(),
            witness: self.witness,
            state,
            term,
            leader,
        }
    }
}

/// The cluster routes, Raft's included.
pub fn router(shared: Arc<Shared>) -> Router {
    let raft = routes::router(Arc::clone(&shared.raft));
    Router::new()
        .route(NODE_PATH, get(node))
        .route(STATS_PATH, get(stats))
        .fallback(not_found)
        .with_state(shared)
        .merge(raft)
}

async fn node(State(shared): State<Arc<Shared>>) -> Json<NodeInfo> {
    Json(shared.info())
}

/// This node's statistics, with long top lists for merging.
async fn stats(State(shared): State<Arc<Shared>>, Query(query): Query<StatsQuery>) -> Response {
    let Some(log) = shared.log.clone() else {
        return error(
            StatusCode::NOT_FOUND,
            "witness",
            format!("{} is a witness: it answers no DNS", shared.node),
        );
    };
    let hours = query.hours.clamp(1, 720);
    match tokio::task::spawn_blocking(move || log.stats_top(hours, TOP_FOR_MERGE)).await {
        Ok(report) => Json(report).into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "cannot read the statistics".into(),
        ),
    }
}

async fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such cluster endpoint".into(),
    )
}

fn error(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(WireError {
            code: code.to_owned(),
            message,
        }),
    )
        .into_response()
}
