//! OpenTelemetry (ADR 0040). The node's metrics are kept by the OpenTelemetry
//! SDK and served at `/metrics` in the Prometheus text format, under the same
//! names as before.
//!
//! A query's counters are bound instruments ([`QueryMetrics`]). Everything
//! else is read from its owner when the metrics are collected: the data
//! plane's parts directly, and what the control plane owns (the filter, the
//! lists, the query log) through the [`Node`] it publishes while it runs.
//!
//! With `[telemetry] endpoint` set, the metrics and the log records
//! ([`logs`]) are also sent to an OpenTelemetry collector over OTLP/HTTP
//! ([`otlp`]).

pub(crate) mod logs;
pub(crate) mod otlp;
mod queries;
pub(crate) mod traces;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use goethite_resolver::{Resolver, Transport, UpstreamStatus};
use goethite_server::ServerStats;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{AsyncInstrument, Meter, MeterProvider as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tracing::warn;

use crate::config::Config;
use crate::node::Node;
use crate::observe::protocol;
use crate::secrets::Secrets;
use otlp::{Export, Exports};

pub(crate) use queries::QueryMetrics;

/// The meter provider, its instruments and the registry `/metrics` reads;
/// and the logger provider, when log records go to a collector.
pub(crate) struct Telemetry {
    /// Kept for as long as the metrics are: dropping it shuts it down.
    provider: SdkMeterProvider,
    /// Sends log records to the collector, if they go there.
    logs: Option<SdkLoggerProvider>,
    meter: Meter,
    registry: prometheus::Registry,
    queries: Arc<QueryMetrics>,
    /// The control plane's node, while it runs.
    node: Arc<ArcSwapOption<Node>>,
    started: SystemTime,
    /// How the requests to the collector fare, by signal.
    requests: Vec<(&'static str, Arc<Exports>)>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry").finish_non_exhaustive()
    }
}

impl Telemetry {
    /// The metrics for a node run with `config`: served at `/metrics`, and
    /// sent with the log records to the collector `[telemetry]` names, if it
    /// names one. Call it on the runtime, after the sandbox is applied: the
    /// exports run on threads of their own.
    ///
    /// # Errors
    ///
    /// If the export cannot be set up (its headers or CA are unusable).
    pub(crate) fn from_config(
        config: &Config,
        secrets: &Secrets,
        resolver: &Arc<Resolver>,
    ) -> Result<Self> {
        let instance = config
            .cluster
            .as_ref()
            .map(|cluster| cluster.node.to_string());
        let resource = resource(instance);
        let mut export = otlp::export(&config.telemetry, secrets, resolver, &resource)?;
        if let Some(logs) = &export.logs {
            logs::export_to(logs);
        }
        if let Some(processor) = export.traces.take() {
            traces::export_to(processor, config.telemetry.trace_sample_ratio, &resource);
        }
        Self::build(resource, export)
    }

    /// A meter provider with the per-query instruments, served at
    /// `/metrics` only. `instance` names this node (its cluster name), if
    /// it has one.
    ///
    /// # Errors
    ///
    /// If the Prometheus registry refuses the exporter, which never happens
    /// with a fresh registry.
    #[cfg(test)]
    pub(crate) fn new(instance: Option<String>) -> Result<Self> {
        Self::build(resource(instance), Export::default())
    }

    fn build(resource: Resource, export: Export) -> Result<Self> {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_target_info()
            .scope_info_enabled(false)
            .build()
            .context("cannot set up the metrics")?;
        let mut provider = SdkMeterProvider::builder()
            .with_reader(exporter)
            .with_resource(resource);
        if let Some(reader) = export.metrics {
            provider = provider.with_reader(reader);
        }
        let provider = provider.build();
        let meter = provider.meter("goethite");
        let queries = Arc::new(QueryMetrics::new(&meter));
        Ok(Self {
            provider,
            logs: export.logs,
            meter,
            registry,
            queries,
            node: Arc::new(ArcSwapOption::empty()),
            started: SystemTime::now(),
            requests: export.requests,
        })
    }

    /// The per-query instruments, for the query observer.
    pub(crate) fn queries(&self) -> Arc<QueryMetrics> {
        Arc::clone(&self.queries)
    }

    /// Where the control plane publishes its node while it runs, and takes
    /// it back when it stops.
    pub(crate) fn node(&self) -> Arc<ArcSwapOption<Node>> {
        Arc::clone(&self.node)
    }

    /// The registry the metrics are read from, for `/metrics`.
    pub(crate) fn registry(&self) -> prometheus::Registry {
        self.registry.clone()
    }

    /// Adds the instruments read at collection time: the listeners, the
    /// resolver, the control plane's state and the build.
    pub(crate) fn observe(&self, resolver: &Arc<Resolver>, server: &Arc<ServerStats>) {
        listeners(&self.meter, server);
        resolution(&self.meter, resolver);
        control_plane(&self.meter, &self.node);
        if !self.requests.is_empty() {
            let requests = self.requests.clone();
            counter(
                &self.meter,
                "goethite.telemetry.export_failures",
                "Requests to the OpenTelemetry collector that failed (retries included), by \
                 signal.",
                move |o| {
                    for (signal, exports) in &requests {
                        o.observe(exports.failed(), &[KeyValue::new("signal", *signal)]);
                    }
                },
            );
        }
        let version = KeyValue::new("version", env!("CARGO_PKG_VERSION"));
        gauge(
            &self.meter,
            "goethite.build.info",
            "The running version.",
            move |o| o.observe(1, std::slice::from_ref(&version)),
        );
        let started = self
            .started
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        self.meter
            .u64_observable_gauge("goethite.start_time")
            .with_unit("s")
            .with_description("When goethite started, in seconds since the Unix epoch.")
            .with_callback(move |o| o.observe(started, &[]))
            .build();
    }

    /// Stops the providers, sending what is left to the collector if
    /// telemetry goes there. Blocks until that is done or has timed out.
    pub(crate) fn shutdown(&self) {
        if let Err(err) = self.provider.shutdown() {
            warn!(%err, "could not send the metrics a last time");
        }
        if let Err(err) = traces::shutdown() {
            warn!(%err, "could not send the last spans");
        }
        if let Some(logs) = &self.logs
            && let Err(err) = logs.shutdown()
        {
            warn!(%err, "could not send the last log records");
        }
    }
}

/// What every export says about where it comes from: goethite, its version,
/// and the node's name in its cluster, if it is in one.
fn resource(instance: Option<String>) -> Resource {
    let mut resource = Resource::builder_empty()
        .with_service_name("goethite")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")));
    if let Some(instance) = instance {
        resource = resource.with_attribute(KeyValue::new("service.instance.id", instance));
    }
    resource.build()
}

/// The metrics in the Prometheus text format.
pub(crate) fn render(registry: &prometheus::Registry) -> String {
    let mut text = String::with_capacity(8192);
    if let Err(err) = prometheus::TextEncoder::new().encode_utf8(&registry.gather(), &mut text) {
        warn!(%err, "cannot write the metrics");
    }
    text
}

/// An observable counter read by `read`.
fn counter(
    meter: &Meter,
    name: &'static str,
    help: &'static str,
    read: impl Fn(&dyn AsyncInstrument<u64>) + Send + Sync + 'static,
) {
    meter
        .u64_observable_counter(name)
        .with_description(help)
        .with_callback(read)
        .build();
}

/// An observable gauge read by `read`.
fn gauge(
    meter: &Meter,
    name: &'static str,
    help: &'static str,
    read: impl Fn(&dyn AsyncInstrument<u64>) + Send + Sync + 'static,
) {
    meter
        .u64_observable_gauge(name)
        .with_description(help)
        .with_callback(read)
        .build();
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// What the DNS listeners turned away.
fn listeners(meter: &Meter, server: &Arc<ServerStats>) {
    for (name, help, by_transport) in [
        (
            "goethite.rate_limited",
            "Queries over the rate limit, by protocol: dropped over UDP (or answered truncated), \
             refused otherwise.",
            (|s: &ServerStats| &s.rate_limited)
                as fn(&ServerStats) -> &goethite_server::ByTransport,
        ),
        (
            "goethite.access_refused",
            "Queries and connections the access lists refused, by protocol.",
            |s: &ServerStats| &s.access_refused,
        ),
    ] {
        let server = Arc::clone(server);
        counter(meter, name, help, move |o| {
            for transport in goethite_server::Transport::ALL {
                let protocol = KeyValue::new("protocol", protocol(transport).as_str());
                o.observe(by_transport(&server).get(transport), &[protocol]);
            }
        });
    }
    for (name, help, read) in [
        (
            "goethite.rate_limit.slips",
            "Truncated answers sent to rate-limited clients.",
            (|s: &ServerStats| &s.rate_limit_slips)
                as fn(&ServerStats) -> &std::sync::atomic::AtomicU64,
        ),
        (
            "goethite.udp.overloaded",
            "UDP queries dropped because too many were in flight.",
            |s: &ServerStats| &s.udp_overloaded,
        ),
        (
            "goethite.udp.oversized",
            "UDP datagrams too large to be a query.",
            |s: &ServerStats| &s.udp_oversized,
        ),
        (
            "goethite.tls.handshake_failures",
            "DNS over TLS and HTTPS connections whose TLS handshake failed or took too long.",
            |s: &ServerStats| &s.tls_handshake_failures,
        ),
        (
            "goethite.https.rejected",
            "DNS over HTTPS requests answered with an HTTP error.",
            |s: &ServerStats| &s.https_rejected,
        ),
    ] {
        let server = Arc::clone(server);
        counter(meter, name, help, move |o| {
            o.observe(
                read(&server).load(std::sync::atomic::Ordering::Relaxed),
                &[],
            );
        });
    }
    let server = Arc::clone(server);
    counter(
        meter,
        "goethite.tcp.refused",
        "TCP connections closed on accept, by limit.",
        move |o| {
            let relaxed = std::sync::atomic::Ordering::Relaxed;
            o.observe(
                server.tcp_refused.load(relaxed),
                &[KeyValue::new("limit", "total")],
            );
            o.observe(
                server.tcp_refused_per_client.load(relaxed),
                &[KeyValue::new("limit", "per_client")],
            );
        },
    );
}

/// The cache, the upstreams, recursion and filtering failures.
fn resolution(meter: &Meter, resolver: &Arc<Resolver>) {
    if resolver.cache().is_some() {
        let r = Arc::clone(resolver);
        gauge(
            meter,
            "goethite.cache.entries",
            "Answers in the cache.",
            move |o| {
                if let Some(cache) = r.cache() {
                    o.observe(as_u64(cache.len()), &[]);
                }
            },
        );
        let r = Arc::clone(resolver);
        counter(
            meter,
            "goethite.cache.lookups",
            "Cache lookups, by result.",
            move |o| {
                if let Some(cache) = r.cache() {
                    let stats = cache.stats();
                    o.observe(stats.hits, &[KeyValue::new("result", "hit")]);
                    o.observe(stats.misses, &[KeyValue::new("result", "miss")]);
                }
            },
        );
    }
    if resolver.forwarder().is_some() {
        let r = Arc::clone(resolver);
        gauge(
            meter,
            "goethite.upstream.up",
            "1 if the upstream is in use, 0 while it is skipped after failures.",
            move |o| {
                for upstream in upstreams(&r) {
                    o.observe(u64::from(upstream.healthy), &upstream_labels(&upstream));
                }
            },
        );
        let r = Arc::clone(resolver);
        gauge(
            meter,
            "goethite.upstream.consecutive_failures",
            "Failures since the upstream last answered.",
            move |o| {
                for upstream in upstreams(&r) {
                    o.observe(
                        u64::from(upstream.consecutive_failures),
                        &upstream_labels(&upstream),
                    );
                }
            },
        );
    }
    if resolver.recursor().is_some() {
        recursion(meter, resolver);
    }
    let r = Arc::clone(resolver);
    counter(
        meter,
        "goethite.filter.failures",
        "Queries whose filtering failed (a bug), answered as [filter] on_failure says.",
        move |o| o.observe(r.filter_failures(), &[]),
    );
}

fn recursion(meter: &Meter, resolver: &Arc<Resolver>) {
    let stats = |r: &Resolver| r.recursor().map(goethite_resolver::Recursor::stats);
    let r = Arc::clone(resolver);
    counter(
        meter,
        "goethite.recursion.queries",
        "Queries sent to authoritative servers, by protocol.",
        move |o| {
            if let Some(stats) = stats(&r) {
                let udp = stats.sent.saturating_sub(stats.tcp);
                o.observe(udp, &[KeyValue::new("protocol", "udp")]);
                o.observe(stats.tcp, &[KeyValue::new("protocol", "tcp")]);
            }
        },
    );
    let r = Arc::clone(resolver);
    counter(
        meter,
        "goethite.recursion.timeouts",
        "Queries to authoritative servers that got no answer in time.",
        move |o| {
            if let Some(stats) = stats(&r) {
                o.observe(stats.timeouts, &[]);
            }
        },
    );
    let r = Arc::clone(resolver);
    counter(
        meter,
        "goethite.recursion.failures",
        "Client queries recursion could not resolve (SERVFAIL).",
        move |o| {
            if let Some(stats) = stats(&r) {
                o.observe(stats.failures, &[]);
            }
        },
    );
    let r = Arc::clone(resolver);
    counter(
        meter,
        "goethite.recursion.dnssec",
        "Answers DNSSEC validation found secure, insecure or bogus (bogus ones are SERVFAIL).",
        move |o| {
            if let Some(stats) = stats(&r) {
                for (result, count) in [
                    ("secure", stats.secure),
                    ("insecure", stats.insecure),
                    ("bogus", stats.bogus),
                ] {
                    o.observe(count, &[KeyValue::new("result", result)]);
                }
            }
        },
    );
    let r = Arc::clone(resolver);
    gauge(
        meter,
        "goethite.recursion.zones",
        "Zone cuts recursion knows.",
        move |o| {
            if let Some(stats) = stats(&r) {
                o.observe(as_u64(stats.zones), &[]);
            }
        },
    );
}

fn upstreams(resolver: &Resolver) -> Vec<UpstreamStatus> {
    resolver
        .forwarder()
        .map(goethite_resolver::Forwarder::upstreams)
        .unwrap_or_default()
}

fn upstream_labels(upstream: &UpstreamStatus) -> [KeyValue; 2] {
    let protocol = match &upstream.config.transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Tls { .. } => "tls",
        Transport::Https { .. } => "https",
        _ => "other",
    };
    [
        KeyValue::new("upstream", upstream.config.address.to_string()),
        KeyValue::new("protocol", protocol),
    ]
}

/// What the control plane owns, read from its node while it runs. While it
/// is stopped (during an upgrade), these report nothing.
fn control_plane(meter: &Meter, node: &Arc<ArcSwapOption<Node>>) {
    let n = Arc::clone(node);
    gauge(
        meter,
        "goethite.filter.rules",
        "Rules in the compiled filter.",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                o.observe(as_u64(node.control.compiled().filter.rule_count()), &[]);
            }
        },
    );
    let n = Arc::clone(node);
    gauge(
        meter,
        "goethite.filter.lists",
        "Filter lists, by state.",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                let config = node.control.store().config();
                let enabled = config.lists.iter().filter(|list| list.spec.enabled).count();
                let disabled = config.lists.len().saturating_sub(enabled);
                o.observe(as_u64(enabled), &[KeyValue::new("state", "enabled")]);
                o.observe(as_u64(disabled), &[KeyValue::new("state", "disabled")]);
            }
        },
    );
    let n = Arc::clone(node);
    gauge(
        meter,
        "goethite.protection.enabled",
        "1 if filtering is on in the settings.",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                let on = node.control.store().config().settings.spec.protection;
                o.observe(u64::from(on), &[]);
            }
        },
    );
    let n = Arc::clone(node);
    gauge(
        meter,
        "goethite.protection.paused",
        "1 while filtering is paused.",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                let paused = node.control.state().paused_until().is_some();
                o.observe(u64::from(paused), &[]);
            }
        },
    );
    let n = Arc::clone(node);
    counter(
        meter,
        "goethite.querylog.dropped",
        "Query log events dropped because the writer could not keep up.",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                o.observe(node.log.dropped(), &[]);
            }
        },
    );
    let n = Arc::clone(node);
    gauge(
        meter,
        "goethite.degraded",
        "1 while the node reports problems (see /api/v1/status).",
        move |o| {
            if let Some(node) = n.load().as_ref() {
                o.observe(u64::from(node.degraded()), &[]);
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use goethite_resolver::{
        Cache, CacheConfig, Forwarder, ForwarderConfig, Recursor, RecursorConfig, UpstreamConfig,
    };
    use goethite_store::{Protocol, QueryOutcome};

    use super::*;

    /// The metrics of a node with `resolver` and `server`, after `queries`.
    fn rendered(
        resolver: Resolver,
        server: ServerStats,
        queries: impl FnOnce(&QueryMetrics),
    ) -> String {
        let telemetry = Telemetry::new(Some("dns1".into())).unwrap();
        telemetry.observe(&Arc::new(resolver), &Arc::new(server));
        queries(&telemetry.queries());
        render(&telemetry.registry())
    }

    fn assert_lines(text: &str, lines: &[String]) {
        for line in lines {
            assert!(
                text.lines().any(|l| l == line),
                "missing {line:?} in\n{text}"
            );
        }
    }

    /// The names, labels and types v0.5.0 served by hand, now from the SDK.
    #[test]
    fn keeps_the_prometheus_names() {
        let upstream = UpstreamConfig::udp("9.9.9.9:53".parse().unwrap());
        let resolver = Resolver::new(Vec::new())
            .with_cache(Cache::new(CacheConfig::default()))
            .with_forwarder(Forwarder::new(ForwarderConfig::new(vec![upstream])).unwrap());
        let server = ServerStats::default();
        for _ in 0..4 {
            server.rate_limited.count(goethite_server::Transport::Udp);
        }
        server
            .access_refused
            .count(goethite_server::Transport::Https);
        server.tls_handshake_failures.store(2, Ordering::Relaxed);
        let text = rendered(resolver, server, |queries| {
            queries.observe(
                QueryOutcome::Blocked,
                Protocol::Udp,
                Duration::from_micros(80),
            );
            queries.observe(
                QueryOutcome::Forwarded,
                Protocol::Tcp,
                Duration::from_millis(30),
            );
            queries.observe(
                QueryOutcome::Forwarded,
                Protocol::Tcp,
                Duration::from_secs(9),
            );
            queries.observe(
                QueryOutcome::Cached,
                Protocol::Doh,
                Duration::from_micros(80),
            );
        });
        let version = env!("CARGO_PKG_VERSION");
        assert_lines(
            &text,
            &[
                "goethite_queries_total{outcome=\"blocked\",protocol=\"udp\"} 1",
                "goethite_queries_total{outcome=\"forwarded\",protocol=\"tcp\"} 2",
                "goethite_queries_total{outcome=\"cached\",protocol=\"doh\"} 1",
                "goethite_queries_total{outcome=\"cached\",protocol=\"dot\"} 0",
                "goethite_query_duration_seconds_bucket{le=\"0.0001\"} 2",
                "goethite_query_duration_seconds_bucket{le=\"0.05\"} 3",
                "goethite_query_duration_seconds_bucket{le=\"2.5\"} 3",
                "goethite_query_duration_seconds_bucket{le=\"+Inf\"} 4",
                "goethite_query_duration_seconds_count 4",
                "goethite_rate_limited_total{protocol=\"udp\"} 4",
                "goethite_rate_limited_total{protocol=\"dot\"} 0",
                "goethite_access_refused_total{protocol=\"doh\"} 1",
                "goethite_tls_handshake_failures_total 2",
                "goethite_tcp_refused_total{limit=\"per_client\"} 0",
                "goethite_cache_entries 0",
                "goethite_cache_lookups_total{result=\"hit\"} 0",
                "goethite_upstream_up{protocol=\"udp\",upstream=\"9.9.9.9:53\"} 1",
                "goethite_upstream_consecutive_failures{protocol=\"udp\",upstream=\"9.9.9.9:53\"} 0",
                "goethite_filter_failures_total 0",
                "# HELP goethite_queries_total Answered queries, by outcome and protocol.",
                "# TYPE goethite_queries_total counter",
                "# TYPE goethite_query_duration_seconds histogram",
                "# TYPE goethite_upstream_up gauge",
            ]
            .map(String::from),
        );
        assert_lines(
            &text,
            &[format!("goethite_build_info{{version=\"{version}\"}} 1")],
        );
        let sum = text
            .lines()
            .find_map(|l| l.strip_prefix("goethite_query_duration_seconds_sum "))
            .unwrap();
        assert!(
            (sum.parse::<f64>().unwrap() - 9.03016).abs() < 1e-9,
            "{sum}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("goethite_start_time_seconds ")),
            "{text}"
        );
        // Nothing OpenTelemetry adds by default, and no control plane yet.
        assert!(!text.contains("otel_scope"), "{text}");
        assert!(!text.contains("target_info"), "{text}");
        assert!(!text.contains("goethite_filter_rules"), "{text}");
        // Every sample line is a name, optional labels and a number.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn recursion_metrics() {
        let resolver =
            Resolver::new(Vec::new()).with_recursor(Recursor::new(RecursorConfig::default()));
        let text = rendered(resolver, ServerStats::default(), |_| {});
        assert_lines(
            &text,
            &[
                "goethite_recursion_queries_total{protocol=\"udp\"} 0",
                "goethite_recursion_queries_total{protocol=\"tcp\"} 0",
                "goethite_recursion_timeouts_total 0",
                "goethite_recursion_failures_total 0",
                "goethite_recursion_dnssec_total{result=\"bogus\"} 0",
            ]
            .map(String::from),
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("goethite_recursion_zones ")),
            "{text}"
        );
        assert!(!text.contains("goethite_upstream_up"), "{text}");
        assert!(!text.contains("goethite_cache_entries"), "{text}");
    }
}
