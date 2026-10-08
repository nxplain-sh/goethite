//! The cluster listener's routes: what a node answers its peer.
//!
//! The listener itself (TLS, connection limits) is the API server's, with
//! the mutual-TLS configuration from [`crate::Identity::server_config`], so
//! every request here comes from the configured peer.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use goethite_store::Store;
use jiff::Timestamp;
use tokio::sync::watch;

use crate::node::{NodeId, Role};
use crate::wire::{CONFIG_PATH, ConfigQuery, MAX_WAIT_SECS, NODE_PATH, NodeInfo, WireError};

/// What the cluster routes need.
pub struct Shared {
    /// This node's name.
    pub node: NodeId,
    /// This node's role; it can change at run time.
    pub role: watch::Receiver<Role>,
    /// The store.
    pub store: Arc<Store>,
    /// When this node started.
    pub started_at: Timestamp,
}

impl Shared {
    /// This node, as its peer sees it.
    pub fn info(&self) -> NodeInfo {
        NodeInfo {
            node: self.node.clone(),
            role: *self.role.borrow(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at: self.started_at,
            config: self.store.version(),
        }
    }
}

/// The cluster routes.
pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route(NODE_PATH, get(node))
        .route(CONFIG_PATH, get(config))
        .fallback(not_found)
        .with_state(shared)
}

async fn node(State(shared): State<Arc<Shared>>) -> Json<NodeInfo> {
    Json(shared.info())
}

/// The configuration, once it is newer than the replica's: at once if it
/// already is, otherwise when it changes, or 204 after `wait` seconds.
async fn config(State(shared): State<Arc<Shared>>, Query(query): Query<ConfigQuery>) -> Response {
    if *shared.role.borrow() != Role::Primary {
        return error(
            StatusCode::CONFLICT,
            "not_primary",
            format!("{} is not the primary", shared.node),
        );
    }
    let have = query.have();
    let mut changes = shared.store.subscribe();
    let wait = Duration::from_secs(query.wait.min(MAX_WAIT_SECS));
    // The watch guard must not live across an await: map it away at once.
    let newer = tokio::time::timeout(wait, async {
        changes
            .wait_for(|current| current.replaces(have))
            .await
            .is_ok()
    })
    .await;
    match newer {
        Ok(true) => {
            let store = Arc::clone(&shared.store);
            match tokio::task::spawn_blocking(move || store.export()).await {
                Ok(export) => Json(export).into_response(),
                Err(_) => error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "cannot export the configuration".into(),
                ),
            }
        }
        // No change in time; the replica asks again.
        Err(_) => StatusCode::NO_CONTENT.into_response(),
        // The store is gone: this node is shutting down.
        Ok(false) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "shutting down".into(),
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
