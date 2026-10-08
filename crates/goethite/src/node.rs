//! The node as the API sees it: status, changes, pausing and metrics.

use std::sync::Arc;
use std::time::SystemTime;

use goethite_api::{
    BoxFuture, BoxResult, CacheStatus, Change, ClusterRole, ClusterStatus, FilterStatus, Forwarded,
    ForwardedAnswer, ListStatus, QueryLogStatus, Status, UpstreamStatus, Writes,
};
use goethite_resolver::{Resolver, Transport};
use goethite_server::ServerStats;
use goethite_store::{Actor, QueryLog};
use jiff::Timestamp;
use tracing::warn;

use crate::cluster::Cluster;
use crate::control::Control;
use crate::metrics::{self, Metrics};

/// Everything the API reports on and acts through.
pub struct Node {
    /// The control plane.
    pub control: Arc<Control>,
    /// The resolver, for the cache and upstreams.
    pub resolver: Arc<Resolver>,
    /// What the DNS listeners turned away.
    pub server: Arc<ServerStats>,
    /// Per-query counters.
    pub metrics: Arc<Metrics>,
    /// The query log.
    pub log: Arc<QueryLog>,
    /// Whether queries are logged.
    pub querylog_enabled: bool,
    /// When goethite started.
    pub started: Timestamp,
    /// This node's cluster, if it is in one.
    pub cluster: Option<Arc<Cluster>>,
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl goethite_api::Control for Node {
    fn status(&self) -> Status {
        let compiled = self.control.compiled();
        let config = self.control.store().config();
        let statuses = self.control.list_statuses();
        let lists = config
            .lists
            .iter()
            .map(|list| {
                let status = statuses.get(&list.id).cloned().unwrap_or_default();
                ListStatus {
                    id: list.id.clone(),
                    rules: status.stats.map(|stats| as_u64(stats.rules)),
                    unsupported: status.stats.map(|stats| as_u64(stats.unsupported)),
                    invalid: status.stats.map(|stats| as_u64(stats.invalid)),
                    error: status.error,
                    last_attempt: status.last_attempt,
                    last_success: status.last_success,
                    download_error: status.download_error,
                }
            })
            .collect();
        let upstreams = self
            .resolver
            .forwarder()
            .map(|forwarder| {
                forwarder
                    .upstreams()
                    .into_iter()
                    .map(|upstream| UpstreamStatus {
                        address: upstream.config.address.to_string(),
                        protocol: protocol(&upstream.config.transport).into(),
                        healthy: upstream.healthy,
                        consecutive_failures: upstream.consecutive_failures,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let cache = self.resolver.cache().map(|cache| {
            let stats = cache.stats();
            CacheStatus {
                entries: as_u64(cache.len()),
                hits: stats.hits,
                misses: stats.misses,
            }
        });
        let entries = self.control.store().query_log_len().unwrap_or_else(|err| {
            warn!(%err, "cannot count the query log");
            0
        });
        Status {
            version: env!("CARGO_PKG_VERSION").into(),
            started_at: self.started,
            protection: config.settings.spec.protection,
            paused_until: self
                .control
                .state()
                .paused_until()
                .and_then(|until| Timestamp::try_from(until).ok()),
            filter: FilterStatus {
                rules: as_u64(compiled.filter.rule_count()),
                memory_bytes: as_u64(compiled.filter.memory_bytes()),
            },
            lists,
            upstreams,
            cache,
            query_log: QueryLogStatus {
                enabled: self.querylog_enabled,
                entries,
                dropped: self.log.dropped(),
            },
            cluster: self.cluster.as_ref().map(|cluster| cluster.status()),
        }
    }

    fn apply(&self, change: Change) -> BoxFuture<'_> {
        Box::pin(async move {
            match change {
                Change::Filter => self.control.rebuild_filter().await,
                Change::Policy => self.control.rebuild_policy(),
            }
        })
    }

    fn refresh_lists(&self) {
        self.control.refresh_lists();
    }

    fn pause(&self, until: Option<SystemTime>) {
        self.control.state().pause(until);
    }

    fn paused_until(&self) -> Option<SystemTime> {
        self.control.state().paused_until()
    }

    fn cluster(&self) -> Option<ClusterStatus> {
        self.cluster.as_ref().map(|cluster| cluster.status())
    }

    fn writes(&self) -> Writes {
        self.cluster
            .as_ref()
            .map_or(Writes::Local, |cluster| cluster.writes())
    }

    fn forward(&self, forwarded: Forwarded) -> BoxResult<'_, ForwardedAnswer> {
        Box::pin(async move {
            match &self.cluster {
                Some(cluster) => cluster.forward(forwarded).await,
                None => Err(goethite_api::ApiError::not_found(
                    "this node is not in a cluster",
                )),
            }
        })
    }

    fn set_role(
        &self,
        role: ClusterRole,
        force: bool,
        actor: Actor,
    ) -> BoxResult<'_, ClusterStatus> {
        Box::pin(async move {
            match &self.cluster {
                Some(cluster) => cluster.set_role(role, force, actor).await,
                None => Err(goethite_api::ApiError::not_found(
                    "this node is not in a cluster",
                )),
            }
        })
    }

    fn metrics(&self) -> String {
        let config = self.control.store().config();
        let upstreams = self
            .resolver
            .forwarder()
            .map(goethite_resolver::Forwarder::upstreams)
            .unwrap_or_default();
        metrics::render(&metrics::Sources {
            metrics: &self.metrics,
            server: &self.server,
            cache: self
                .resolver
                .cache()
                .map(|cache| (cache.stats(), cache.len())),
            upstreams: &upstreams,
            filter_rules: self.control.compiled().filter.rule_count(),
            lists: (
                config.lists.len(),
                config.lists.iter().filter(|list| list.spec.enabled).count(),
            ),
            protection: (
                config.settings.spec.protection,
                self.control.state().paused_until().is_some(),
            ),
            querylog_dropped: self.log.dropped(),
        })
    }
}

fn protocol(transport: &Transport) -> &'static str {
    match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Tls { .. } => "tls",
        Transport::Https { .. } => "https",
        _ => "other",
    }
}
