//! The node as the API sees it: status, changes, pausing and metrics.

use std::sync::Arc;
use std::time::SystemTime;

use goethite_api::catalog::{Directory, DirectoryList};
use goethite_api::leak::LeakTests;
use goethite_api::recommended::RecommendedSizes;
use goethite_api::{
    ApiError, BoxFuture, BoxResult, CacheStatus, Change, ClusterRole, ClusterStatus,
    EncryptedStatus, FilterStatus, Forwarded, ForwardedAnswer, ListStatus, MemberStats,
    QueryLogStatus, RecursionStatus, Status, UpstreamStatus, Writes,
};
use goethite_resolver::{Resolver, Transport};
use goethite_store::{Actor, QueryLog};
use jiff::Timestamp;
use tracing::warn;

use crate::cluster::Cluster;
use crate::control::Control;
use crate::filterlists::FilterLists;
use crate::sizes::ListSizes;
use crate::telemetry;

/// Everything the API reports on and acts through.
pub(crate) struct Node {
    /// The control plane.
    pub control: Arc<Control>,
    /// The resolver, for the cache and upstreams.
    pub resolver: Arc<Resolver>,
    /// The metrics, for `/metrics`.
    pub metrics: prometheus::Registry,
    /// The query log.
    pub log: Arc<QueryLog>,
    /// Whether queries are logged.
    pub querylog_enabled: bool,
    /// When goethite started.
    pub started: Timestamp,
    /// This node's cluster, if it is in one.
    pub cluster: Option<Arc<Cluster>>,
    /// Why the store file is not in use, if it is not.
    pub store_problem: Option<String>,
    /// DNS over TLS and HTTPS, if they are served.
    pub encrypted: Option<EncryptedStatus>,
    /// The FilterLists directory, unless turned off.
    pub filterlists: Option<Arc<FilterLists>>,
    /// The recommended lists' sizes, unless looking lists up is turned off.
    pub sizes: Option<Arc<ListSizes>>,
    /// DNS leak tests.
    pub leak: Arc<LeakTests>,
}

impl Node {
    /// What is wrong with this node, in words, for people to look at.
    fn problems(&self) -> Vec<String> {
        let mut problems: Vec<String> = self.store_problem.iter().cloned().collect();
        problems.extend(self.control.build_error());
        let failures = self.resolver.filter_failures();
        if failures > 0 {
            problems.push(format!(
                "filtering a query failed {failures} times, which is a bug: please report it \
                 (with the log); those queries were answered as [filter] on_failure says"
            ));
        }
        problems
    }

    /// Whether this node reports problems.
    pub(crate) fn degraded(&self) -> bool {
        !self.problems().is_empty()
    }
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
            recursion: self.resolver.recursor().map(|recursor| {
                let stats = recursor.stats();
                RecursionStatus {
                    qname_minimisation: recursor.config().qname_minimisation,
                    ipv6: recursor.config().ipv6,
                    dnssec: recursor.config().dnssec,
                    sent: stats.sent,
                    tcp: stats.tcp,
                    timeouts: stats.timeouts,
                    failures: stats.failures,
                    secure: stats.secure,
                    insecure: stats.insecure,
                    bogus: stats.bogus,
                    zones: as_u64(stats.zones),
                    servers: as_u64(stats.servers),
                }
            }),
            cache,
            query_log: QueryLogStatus {
                enabled: self.querylog_enabled,
                entries,
                dropped: self.log.dropped(),
            },
            cluster: self.cluster.as_ref().map(|cluster| cluster.status()),
            encrypted: self.encrypted.clone(),
            // Filled in by the API, which knows whether it serves them.
            api_docs: false,
            problems: self.problems(),
        }
    }

    fn directory(&self) -> BoxResult<'_, Directory> {
        Box::pin(async move {
            let filterlists = self
                .filterlists
                .as_ref()
                .ok_or_else(goethite_api::directory_off)?;
            filterlists
                .directory()
                .await
                .map_err(|err| ApiError::unavailable(format!("FilterLists: {err:#}")))
        })
    }

    fn directory_list(&self, id: u64) -> BoxResult<'_, DirectoryList> {
        Box::pin(async move {
            let filterlists = self
                .filterlists
                .as_ref()
                .ok_or_else(goethite_api::directory_off)?;
            filterlists
                .list(id)
                .await
                .map_err(|err| ApiError::unavailable(format!("FilterLists: {err:#}")))
        })
    }

    fn leak_tests(&self) -> Result<&LeakTests, ApiError> {
        Ok(&self.leak)
    }

    fn services(&self) -> Result<goethite_api::services::Services, ApiError> {
        self.control
            .services()
            .ok_or_else(goethite_api::services_off)
    }

    fn recommended_sizes(&self) -> BoxResult<'_, RecommendedSizes> {
        Box::pin(async move {
            let sizes = self
                .sizes
                .as_ref()
                .ok_or_else(goethite_api::directory_off)?;
            sizes
                .sizes()
                .await
                .map_err(|err| ApiError::unavailable(format!("{err:#}")))
        })
    }

    fn apply(&self, change: Change) -> BoxFuture<'_> {
        Box::pin(async move {
            // In a cluster, every change is put into effect as it is
            // applied, wherever it was made: wait for that.
            if let Some(cluster) = &self.cluster {
                cluster.settled().await;
                return;
            }
            match change {
                Change::Lists => {
                    // Fetch the lists now; the downloader rebuilds the
                    // filter once they are on disk.
                    self.control.refresh_lists();
                    self.control.rebuild_filter().await;
                }
                Change::Filter => {
                    self.control.rebuild_filter().await;
                }
                Change::Policy => {
                    self.control.rebuild_policy();
                }
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
                None => Err(ApiError::not_found("this node is not in a cluster")),
            }
        })
    }

    fn member_stats(&self, hours: u32) -> BoxResult<'_, Vec<MemberStats>> {
        Box::pin(async move {
            match &self.cluster {
                Some(cluster) => Ok(cluster.member_stats(hours).await),
                None => Ok(Vec::new()),
            }
        })
    }

    fn remove_member(&self, node: String, actor: Actor) -> BoxResult<'_, ClusterStatus> {
        Box::pin(async move {
            match &self.cluster {
                Some(cluster) => cluster.remove_member(node, actor).await,
                None => Err(ApiError::not_found("this node is not in a cluster")),
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
                None => Err(ApiError::not_found("this node is not in a cluster")),
            }
        })
    }

    fn metrics(&self) -> String {
        telemetry::render(&self.metrics)
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
