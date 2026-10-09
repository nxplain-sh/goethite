//! Prometheus metrics, written out by hand in the text exposition format.
//!
//! Counters that change per query are atomics updated by the query observer;
//! everything else is read from its owner when metrics are scraped.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use goethite_resolver::{CacheStats, RecursorStats, Transport, UpstreamStatus};
use goethite_server::ServerStats;
use goethite_store::{Protocol, QueryOutcome};

/// Upper bounds of the latency histogram buckets, in microseconds.
const BUCKETS_US: [u64; 14] = [
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000,
];

const PROTOCOLS: [Protocol; Protocol::ALL.len()] = Protocol::ALL;

/// Per-query counters.
#[derive(Debug)]
pub(crate) struct Metrics {
    queries: [[AtomicU64; PROTOCOLS.len()]; QueryOutcome::ALL.len()],
    latency: [AtomicU64; BUCKETS_US.len() + 1],
    latency_sum_us: AtomicU64,
    started: SystemTime,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            queries: Default::default(),
            latency: Default::default(),
            latency_sum_us: AtomicU64::new(0),
            started: SystemTime::now(),
        }
    }
}

impl Metrics {
    /// Counts one answered query.
    pub(crate) fn observe(&self, outcome: QueryOutcome, protocol: Protocol, elapsed: Duration) {
        let outcome_index = QueryOutcome::ALL
            .iter()
            .position(|o| *o == outcome)
            .unwrap_or(0);
        let protocol_index = PROTOCOLS.iter().position(|p| *p == protocol).unwrap_or(0);
        if let Some(counter) = self
            .queries
            .get(outcome_index)
            .and_then(|row| row.get(protocol_index))
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let bucket = BUCKETS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(BUCKETS_US.len());
        if let Some(counter) = self.latency.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(micros, Ordering::Relaxed);
    }
}

/// Everything a scrape reports, gathered from its owners.
pub(crate) struct Sources<'a> {
    /// Per-query counters.
    pub metrics: &'a Metrics,
    /// What the listeners turned away.
    pub server: &'a ServerStats,
    /// The cache's hits and misses and its size, if there is a cache.
    pub cache: Option<(CacheStats, usize)>,
    /// The upstreams and how they are doing.
    pub upstreams: &'a [UpstreamStatus],
    /// Recursion's counters, when it is on.
    pub recursion: Option<RecursorStats>,
    /// Rules in the compiled filter.
    pub filter_rules: usize,
    /// Lists in the store, and how many are enabled.
    pub lists: (usize, usize),
    /// Whether filtering is on, and whether it is paused.
    pub protection: (bool, bool),
    /// Query log events dropped because the writer could not keep up.
    pub querylog_dropped: u64,
    /// Queries whose filtering failed.
    pub filter_failures: u64,
    /// Whether the node reports problems.
    pub degraded: bool,
}

/// Text in the exposition format.
struct Out(String);

impl Out {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &str, value: impl std::fmt::Display) {
        if labels.is_empty() {
            let _ = writeln!(self.0, "{name} {value}");
        } else {
            let _ = writeln!(self.0, "{name}{{{labels}}} {value}");
        }
    }

    fn single(&mut self, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
        self.family(name, kind, help);
        self.sample(name, "", value);
    }
}

/// Writes all metrics in the Prometheus text format.
pub(crate) fn render(sources: &Sources<'_>) -> String {
    let mut out = Out(String::with_capacity(4096));
    queries(&mut out, sources.metrics);
    turned_away(&mut out, sources.server);
    if let Some((stats, entries)) = &sources.cache {
        out.single(
            "goethite_cache_entries",
            "gauge",
            "Answers in the cache.",
            entries,
        );
        out.family(
            "goethite_cache_lookups_total",
            "counter",
            "Cache lookups, by result.",
        );
        out.sample("goethite_cache_lookups_total", "result=\"hit\"", stats.hits);
        out.sample(
            "goethite_cache_lookups_total",
            "result=\"miss\"",
            stats.misses,
        );
    }
    out.family(
        "goethite_upstream_up",
        "gauge",
        "1 if the upstream is in use, 0 while it is skipped after failures.",
    );
    for upstream in sources.upstreams {
        out.sample(
            "goethite_upstream_up",
            &upstream_labels(upstream),
            u8::from(upstream.healthy),
        );
    }
    out.family(
        "goethite_upstream_consecutive_failures",
        "gauge",
        "Failures since the upstream last answered.",
    );
    for upstream in sources.upstreams {
        out.sample(
            "goethite_upstream_consecutive_failures",
            &upstream_labels(upstream),
            upstream.consecutive_failures,
        );
    }
    if let Some(recursion) = &sources.recursion {
        recursion_metrics(&mut out, recursion);
    }
    state(&mut out, sources);
    out.0
}

fn recursion_metrics(out: &mut Out, stats: &RecursorStats) {
    out.family(
        "goethite_recursion_queries_total",
        "counter",
        "Queries sent to authoritative servers, by protocol.",
    );
    let udp = stats.sent.saturating_sub(stats.tcp);
    out.sample("goethite_recursion_queries_total", "protocol=\"udp\"", udp);
    out.sample(
        "goethite_recursion_queries_total",
        "protocol=\"tcp\"",
        stats.tcp,
    );
    out.single(
        "goethite_recursion_timeouts_total",
        "counter",
        "Queries to authoritative servers that got no answer in time.",
        stats.timeouts,
    );
    out.single(
        "goethite_recursion_failures_total",
        "counter",
        "Client queries recursion could not resolve (SERVFAIL).",
        stats.failures,
    );
    out.family(
        "goethite_recursion_dnssec_total",
        "counter",
        "Answers DNSSEC validation found secure, insecure or bogus (bogus ones are SERVFAIL).",
    );
    for (result, count) in [
        ("secure", stats.secure),
        ("insecure", stats.insecure),
        ("bogus", stats.bogus),
    ] {
        out.sample(
            "goethite_recursion_dnssec_total",
            &format!("result=\"{result}\""),
            count,
        );
    }
    out.single(
        "goethite_recursion_zones",
        "gauge",
        "Zone cuts recursion knows.",
        stats.zones,
    );
}

fn queries(out: &mut Out, m: &Metrics) {
    out.family(
        "goethite_queries_total",
        "counter",
        "Answered queries, by outcome and protocol.",
    );
    for (outcome, row) in QueryOutcome::ALL.iter().zip(&m.queries) {
        for (protocol, counter) in PROTOCOLS.iter().zip(row) {
            let protocol = protocol.as_str();
            out.sample(
                "goethite_queries_total",
                &format!("outcome=\"{}\",protocol=\"{protocol}\"", outcome.as_str()),
                counter.load(Ordering::Relaxed),
            );
        }
    }
    let name = "goethite_query_duration_seconds";
    out.family(name, "histogram", "Time to resolve a query.");
    let bucket = format!("{name}_bucket");
    let mut cumulative = 0_u64;
    for (bound, counter) in BUCKETS_US.iter().zip(&m.latency) {
        cumulative = cumulative.saturating_add(counter.load(Ordering::Relaxed));
        out.sample(&bucket, &format!("le=\"{}\"", seconds(*bound)), cumulative);
    }
    if let Some(overflow) = m.latency.last() {
        cumulative = cumulative.saturating_add(overflow.load(Ordering::Relaxed));
    }
    out.sample(&bucket, "le=\"+Inf\"", cumulative);
    out.sample(
        &format!("{name}_sum"),
        "",
        seconds(m.latency_sum_us.load(Ordering::Relaxed)),
    );
    out.sample(&format!("{name}_count"), "", cumulative);
}

fn turned_away(out: &mut Out, server: &ServerStats) {
    for (name, help, counter) in [
        (
            "goethite_rate_limited_total",
            "UDP queries over the rate limit.",
            &server.rate_limited,
        ),
        (
            "goethite_rate_limit_slips_total",
            "Truncated answers sent to rate-limited clients.",
            &server.rate_limit_slips,
        ),
        (
            "goethite_udp_overloaded_total",
            "UDP queries dropped because too many were in flight.",
            &server.udp_overloaded,
        ),
        (
            "goethite_udp_oversized_total",
            "UDP datagrams too large to be a query.",
            &server.udp_oversized,
        ),
        (
            "goethite_tls_handshake_failures_total",
            "DNS over TLS and HTTPS connections whose TLS handshake failed or took too long.",
            &server.tls_handshake_failures,
        ),
        (
            "goethite_https_rejected_total",
            "DNS over HTTPS requests answered with an HTTP error.",
            &server.https_rejected,
        ),
    ] {
        out.single(name, "counter", help, counter.load(Ordering::Relaxed));
    }
    let name = "goethite_tcp_refused_total";
    out.family(
        name,
        "counter",
        "TCP connections closed on accept, by limit.",
    );
    out.sample(
        name,
        "limit=\"total\"",
        server.tcp_refused.load(Ordering::Relaxed),
    );
    out.sample(
        name,
        "limit=\"per_client\"",
        server.tcp_refused_per_client.load(Ordering::Relaxed),
    );
}

fn state(out: &mut Out, sources: &Sources<'_>) {
    out.single(
        "goethite_filter_rules",
        "gauge",
        "Rules in the compiled filter.",
        sources.filter_rules,
    );
    let (lists, enabled) = sources.lists;
    out.family("goethite_filter_lists", "gauge", "Filter lists, by state.");
    out.sample("goethite_filter_lists", "state=\"enabled\"", enabled);
    out.sample(
        "goethite_filter_lists",
        "state=\"disabled\"",
        lists.saturating_sub(enabled),
    );
    out.single(
        "goethite_protection_enabled",
        "gauge",
        "1 if filtering is on in the settings.",
        u8::from(sources.protection.0),
    );
    out.single(
        "goethite_protection_paused",
        "gauge",
        "1 while filtering is paused.",
        u8::from(sources.protection.1),
    );
    out.single(
        "goethite_querylog_dropped_total",
        "counter",
        "Query log events dropped because the writer could not keep up.",
        sources.querylog_dropped,
    );
    out.single(
        "goethite_filter_failures_total",
        "counter",
        "Queries whose filtering failed (a bug), answered as [filter] on_failure says.",
        sources.filter_failures,
    );
    out.single(
        "goethite_degraded",
        "gauge",
        "1 while the node reports problems (see /api/v1/status).",
        u8::from(sources.degraded),
    );
    out.family("goethite_build_info", "gauge", "The running version.");
    out.sample(
        "goethite_build_info",
        &format!("version=\"{}\"", escape(env!("CARGO_PKG_VERSION"))),
        1,
    );
    let started = sources
        .metrics
        .started
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    out.single(
        "goethite_start_time_seconds",
        "gauge",
        "When goethite started, in seconds since the Unix epoch.",
        started,
    );
}

fn upstream_labels(upstream: &UpstreamStatus) -> String {
    let protocol = match &upstream.config.transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Tls { .. } => "tls",
        Transport::Https { .. } => "https",
        _ => "other",
    };
    format!(
        "upstream=\"{}\",protocol=\"{protocol}\"",
        escape(&upstream.config.address.to_string())
    )
}

/// Microseconds as seconds, without trailing zeros.
fn seconds(micros: u64) -> String {
    let whole = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:06}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// A label value with `\`, `"` and newlines escaped.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use goethite_resolver::UpstreamConfig;

    use super::*;

    #[test]
    fn renders_the_text_format() {
        let metrics = Metrics::default();
        metrics.observe(
            QueryOutcome::Blocked,
            Protocol::Udp,
            Duration::from_micros(80),
        );
        metrics.observe(
            QueryOutcome::Forwarded,
            Protocol::Tcp,
            Duration::from_millis(30),
        );
        metrics.observe(
            QueryOutcome::Forwarded,
            Protocol::Tcp,
            Duration::from_secs(9),
        );
        metrics.observe(
            QueryOutcome::Cached,
            Protocol::Doh,
            Duration::from_micros(80),
        );
        let server = ServerStats::default();
        server.rate_limited.store(4, Ordering::Relaxed);
        server.tls_handshake_failures.store(2, Ordering::Relaxed);
        let upstreams = [UpstreamStatus {
            config: UpstreamConfig::udp("9.9.9.9:53".parse().unwrap()),
            healthy: false,
            consecutive_failures: 3,
        }];
        let text = render(&Sources {
            metrics: &metrics,
            server: &server,
            cache: Some((CacheStats { hits: 5, misses: 2 }, 7)),
            upstreams: &upstreams,
            recursion: Some(RecursorStats {
                sent: 10,
                tcp: 1,
                bogus: 3,
                ..RecursorStats::default()
            }),
            filter_rules: 1234,
            lists: (3, 2),
            protection: (true, false),
            querylog_dropped: 0,
            filter_failures: 0,
            degraded: false,
        });
        for line in [
            "goethite_queries_total{outcome=\"blocked\",protocol=\"udp\"} 1",
            "goethite_queries_total{outcome=\"forwarded\",protocol=\"tcp\"} 2",
            "goethite_queries_total{outcome=\"cached\",protocol=\"doh\"} 1",
            "goethite_queries_total{outcome=\"cached\",protocol=\"dot\"} 0",
            "goethite_query_duration_seconds_bucket{le=\"0.0001\"} 2",
            "goethite_query_duration_seconds_bucket{le=\"0.05\"} 3",
            "goethite_query_duration_seconds_bucket{le=\"2.5\"} 3",
            "goethite_query_duration_seconds_bucket{le=\"+Inf\"} 4",
            "goethite_query_duration_seconds_count 4",
            "goethite_query_duration_seconds_sum 9.03016",
            "goethite_rate_limited_total 4",
            "goethite_tls_handshake_failures_total 2",
            "goethite_cache_lookups_total{result=\"hit\"} 5",
            "goethite_upstream_up{upstream=\"9.9.9.9:53\",protocol=\"udp\"} 0",
            "goethite_recursion_queries_total{protocol=\"udp\"} 9",
            "goethite_recursion_queries_total{protocol=\"tcp\"} 1",
            "goethite_recursion_dnssec_total{result=\"bogus\"} 3",
            "goethite_filter_rules 1234",
            "goethite_filter_lists{state=\"disabled\"} 1",
            "# TYPE goethite_query_duration_seconds histogram",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing {line:?} in\n{text}"
            );
        }
        // Every sample line is a name, optional labels and a number.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn seconds_and_escaping() {
        assert_eq!(seconds(100), "0.0001");
        assert_eq!(seconds(2_500_000), "2.5");
        assert_eq!(seconds(1_000_000), "1");
        assert_eq!(seconds(0), "0");
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
