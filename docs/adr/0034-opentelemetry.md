# ADR 0034: Instrument goethite with OpenTelemetry, keeping `/metrics` as it was

- **Status:** Accepted, extends ADR 0007
- **Date:** 2026-10-10

## Context

**What v0.5.0 does.**

- **Metrics:** written by hand in the Prometheus text format from relaxed atomics
  ([ADR 0007](0007-query-log.md)).
- **Logs:** `tracing` lines on stderr.
- **Traces:** none.

**What prompted a change.** Operators who run an OpenTelemetry stack want OTLP for all three
signals from one instrumentation model. `docs/observability-research.md` set that against what
goethite has. It found:

- OTel Rust 0.33 declares metrics and logs stable, and traces Beta.
- The SDK's default per-query metric update costs 20 to 30 times what the atomics cost.
- The OTLP exporter's only built-in HTTPS client brings in `aws-lc-rs` beside goethite's `ring`.
- OTel users can already scrape `/metrics` with the Collector's Prometheus receiver, which was
  tested against v0.5.0.

Its recommendation was to keep the hand-written exposition.

**Constraints** (AGENTS.md):

- No avoidable work per query.
- The data plane never depends on the control plane.
- `ring` is the only crypto provider.
- The sandbox blocks the system resolver.
- Every dependency is justified.

## Decision

goethite instruments itself with the OpenTelemetry SDK (Rust, 0.33). This record covers metrics.
Logs and traces follow through `tracing` bridges, each in its own change.

- **`/metrics` is unchanged for Prometheus.**
  - The SDK's Prometheus reader (`opentelemetry-prometheus`) serves it from its own registry,
    with no `target_info` and no `otel_scope_*` labels.
  - OTel names are chosen so the reader's translation gives v0.5.0's names. For example
    `goethite.queries` with unit `{query}` becomes `goethite_queries_total`, and
    `goethite.query.duration` with unit `s` becomes `goethite_query_duration_seconds`.
  - Families, labels, help, types and values are identical. A test asserts this, and a v0.5.0
    scrape was diffed against the new one.
  - The upstream metrics' labels come out in a different order, which Prometheus ignores.
- **Per query, instruments are bound:** each of the 42 outcome × protocol series is resolved
  once at start, and so is the histogram. An update is then one atomic operation in the SDK, with
  no lock and no attribute hashing. This needs the SDK's
  `experimental_metrics_bound_instruments` feature.
- **Everything else is observable:** read from its owner when collected, as before. What the
  control plane owns is read through the node it publishes while it runs. During an upgrade those
  values are absent, not stale.
- **The meter provider belongs to the data plane.** It is built after the sandbox is applied.
- **Export over OTLP will be opt-in** (nothing leaves a node unless configured). It will go out
  through goethite's own HTTP client, rustls with `ring` and goethite's resolver. Library crates
  keep plain `tracing` and do not depend on OpenTelemetry.

## Alternatives considered

- **Keep the hand-written exposition (the research's recommendation).**
  - For it: the cheapest per query (3.2 ns), with no new dependency, and OTel users are served
    through the Collector.
  - Against it: it leaves goethite with its own metrics code and no shared model for logs and
    traces.
  - It lost on that ground, not on cost.
- **Hand-written exposition, plus OTLP from observable instruments over the same atomics.**
  - For it: no change to the per-query path.
  - Against it: every metric would be defined twice, in the exposition and in OTLP, and the two
    would drift.
- **Unbound instruments**, the SDK's default:
  - 86 ns per query in the same bench, about 6 times the bound cost.
  - A read lock and a hash of the attributes on every query.
- **`prometheus-client`:** Prometheus only, with no path to OTLP.
- **OTLP through `reqwest` or `tonic`:**
  - `reqwest`'s rustls feature brings in `aws-lc-rs`.
  - Both resolve names with the system resolver, which the sandbox blocks and which may be
    goethite itself.

## Consequences

- **Cost per query:** about 11 ns more than v0.5.0 (14.5 ns against 3.2 ns per query, Apple M3
  Pro, busy host). That is about 3% of an in-process cached answer. `benches/query-metrics.rs`
  measures it.
- **Dependencies:**
  - Four crates now: `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-prometheus`,
    `prometheus`; more with OTLP.
  - All are 0.x. Each OTel minor release is a breaking upgrade of every OTel crate together; there
    were six in 20 months.
  - `opentelemetry-prometheus` itself is Beta.
- **An experimental API:** bound instruments may change. If they go, use unbound instruments with
  attribute arrays built at start, after measuring them.
- **Small output differences:**
  - The histogram's sum is a float sum of seconds, not whole microseconds.
  - The SDK's internal logs go through `tracing`.
- **Revisit when:**
  - bound instruments are removed or stabilised;
  - OTel Rust reaches 1.0;
  - a dnsperf run shows the metrics in the tail latency.
