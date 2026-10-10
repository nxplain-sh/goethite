# Observability: OpenTelemetry or not

> **Outcome (2026-10-10):** goethite went OpenTelemetry-native against this report's
> recommendation, keeping `/metrics` unchanged and the per-query cost low with bound instruments.
> See [ADR 0040](adr/0040-opentelemetry.md). The report stands as written.

This report asks whether goethite should use OpenTelemetry (OTel) for metrics, logs and traces.
It compares OTel with what goethite v0.5.0 does today (commit `9cb816c`) and with the realistic
alternatives, as of 2026-10-10. The facts come from primary sources only: crate manifests and
source at pinned tags, each project's own docs, changelogs and issue tracker, the OTel
specification and semantic-conventions repositories, the IETF Datatracker and the IANA registry.
Every claim links to its source. Three things were measured in throwaway crates outside this
repository: the dependency trees (`cargo tree`, `cargo deny`) and the per-query cost of a metric
update. The method is described where each result appears.

| Project | Version read | Released |
| --- | --- | --- |
| OpenTelemetry Rust (`opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `opentelemetry-appender-tracing`, `opentelemetry-prometheus`) | 0.33.1: tag `opentelemetry-0.33.1`, commit `372ebbc` | 2026-10-08 (tag), 2026-10-09 (crates.io) |
| `tracing-opentelemetry` (tokio-rs) | 0.34.0 | 2026-09-23 |
| OTel specification | v1.61.0 | 2026-09-14 |
| OTel semantic conventions | v1.44.0 | 2026-08-04 |
| OTel Collector contrib | v0.162.0 | 2026-09-29 |
| Prometheus | v3.15.0 | 2026-09-25 |
| CoreDNS | v1.14.7 | 2026-08-19 |
| PowerDNS Recursor | 5.4.7 | 2026-10-01 |
| dnsdist | 2.1.2 | 2026-09-08 |
| Unbound | 1.26.1 | 2026-09-16 |
| Knot Resolver | 6.5.0 | 2026-10-01 |
| BIND 9 | 9.20.29 | 2026-09-11 |
| Blocky | v0.35.0 | 2026-09-05 |
| Technitium DNS Server | v15.6 | 2026-10-03 |

In links, `OTEL@372ebbc` means
`github.com/open-telemetry/opentelemetry-rust` at commit
[`372ebbc`](https://github.com/open-telemetry/opentelemetry-rust/tree/372ebbc74d4dba71bb9820732f57f7316b4e7a1e),
which is the tag `opentelemetry-0.33.1` for every crate in that repository.

Contents: [Summary](#summary) · [Recommendation](#recommendation) ·
[goethite today](#goethite-today) · [OpenTelemetry Rust today](#opentelemetry-rust-today) ·
[Dependency cost](#dependency-cost) · [Hot-path cost](#hot-path-cost) ·
[Prometheus interop](#prometheus-interop) · [DNS semantic conventions](#dns-semantic-conventions) ·
[What other DNS servers chose](#what-other-dns-servers-chose) ·
[Tracing a DNS resolver](#tracing-a-dns-resolver) · [Push or pull](#push-or-pull) ·
[Not verified](#not-verified)

## Summary

- **Logs and metrics are stable in OTel Rust; traces are not.** As of 0.33.1 (2026-10-08), the
  API, SDK and OTLP exporter for logs and metrics are stable. The traces API, SDK and exporter are
  Beta, and breaking changes are still landing in them. Every crate is still 0.x, so each minor
  release is a new incompatible version for Cargo. There were six of them between February 2025
  and September 2026, and `tracing-opentelemetry` has to move in step. The MSRV (1.75) is no
  issue.
- **An OTLP exporter adds 13 to 18 crates, and its built-in HTTPS path brings a second crypto
  library.** Every license passes `deny.toml`, and `cargo deny` passes. But the exporter's only
  built-in HTTPS client option, `reqwest-rustls`, pulls in `aws-lc-rs` and `aws-lc-sys`, a C
  build with cmake. goethite uses `ring` only. TLS over `ring` is reachable two ways: through
  gRPC (`tls-ring`), which adds 18 crates and nothing new for TLS, or through an HTTP client
  goethite would write on its own hyper and rustls.
- **The OTel metrics SDK is much more expensive per query than goethite's counters.** A normal
  ("unbound") update takes a read lock, hashes the attribute slice and looks it up in a
  `HashMap`, and a histogram update also takes a `Mutex`. Measured on an Apple M3 Pro, a counter
  plus histogram update per query cost 83–121 ns with OTel and 2.7–5.3 ns with goethite's relaxed
  atomics. On the same machine, goethite's whole in-process cached answer costs about 400 ns.
  The experimental "bound" instruments bring OTel down to 13–21 ns. Neither design allocated on
  the heap.
- **OTel users can consume goethite's existing outputs without an OTel SDK inside goethite.**
  The Collector's `prometheusreceiver` (beta) takes a full Prometheus `scrape_config`. A test with
  Collector 0.162.0 and goethite v0.5.0 confirmed it: the token-protected `/metrics` arrived as
  OTel sums, gauges and a histogram, and a wrong token was refused. Logs reach the Collector
  through the `journaldreceiver` (alpha; it needs the `journalctl` binary) or the
  `filelogreceiver` (beta). Prometheus has accepted OTLP
  natively since 3.0, with the endpoint marked stable, but that serves software that pushes;
  goethite does not need it.
- **OTel defines nothing for DNS servers.** The DNS semantic conventions (v1.44.0) are in
  Development and describe a client doing a lookup: two attributes and one metric,
  `dns.lookup.duration`. That metric requires `dns.question.name`, an unbounded label; an open
  issue asks to make it opt-in. There is no standard to conform to yet.
- **Six of the eight comparable servers checked serve Prometheus metrics themselves, and none
  exports OTLP.** Unbound has only a contrib script, and BIND only a third-party exporter. Only
  PowerDNS (Recursor and dnsdist) produces OTel trace data, and it sends it inside its own
  protobuf logging stream. That feature is experimental and off by default, and since Recursor
  5.4 it covers only queries matching configured clients and names. CoreDNS maintainers turned
  down an OTel plugin: "OTel brings in a lot of excess baggage."
- **Trace context does not cross DNS.** The EDNS `TRACEPARENT` draft exists only in PowerDNS's
  GitHub repository. It was never submitted to the IETF, and IANA has assigned no option code for
  it. A goethite trace would therefore start and end inside goethite, except on the cluster's
  own connections.
- **goethite already records a wide event for every query.** The query log stores the client,
  protocol, name, type, rcode, outcome, upstream, matched rule, group and elapsed time. That
  covers most of what a per-query span would show.
- **Push does not match how the target users collect metrics.** An OTLP push needs a background
  thread for each signal, outgoing connections and credentials. When the collector is down,
  data is dropped once bounded queues fill. Prometheus's docs call pull "slightly better" and
  limit the Pushgateway to batch jobs. Its OTLP receiver is off by default, because Prometheus
  might otherwise accept unauthenticated pushes.

## Recommendation

OpenTelemetry is the right format for interoperability and the wrong thing to put inside
goethite's per-query path. Recommendation per signal:

**Metrics: keep Prometheus pull at `/metrics`, rendered by hand. Do not adopt the OTel metrics
SDK.**

- The target users run Prometheus and Grafana, and nearly every comparable server serves
  Prometheus. OTel shops scrape the same endpoint with the Collector's `prometheusreceiver`,
  which takes the same `scrape_config` the [API docs](../site/src/content/docs/api.md#metrics)
  already show; a sentence saying so is enough.
- The SDK would put a read lock, a hash and (for histograms) a mutex on every query, at about 20
  to 30 times the current cost. That is about a quarter of an in-process cached answer. The fast
  bound instruments are experimental. AGENTS.md asks for no avoidable heap allocation per query
  and for sharded or lock-free structures (said of the cache); plain atomics meet both, with less
  work than any library can do.
- `opentelemetry-prometheus` is Beta. It was deprecated and then reinstated within a year, and its
  own README recommends OTLP for new projects. It would give goethite nothing it does not already have.
- If OTLP push of metrics is ever requested, for example by a site without Prometheus, export from
  the same atomics. Use asynchronous (observable) instruments, which the SDK reads at collection
  time, so the per-query path stays as it is. Make it opt-in, and use gRPC with `tls-ring` or an
  HTTP client goethite writes itself, never `reqwest-rustls`.
- The backlog items (cluster and Raft metrics, sandbox state, read-only monitoring tokens) belong
  in the same exposition.
- Do not adopt `dns.question.name` as a metric label (cardinality), and do not chase the DNS
  conventions while they are in Development.

**Logs: keep `tracing` to stderr and journald, and add the JSON format from the backlog.**

- `tracing-subscriber`'s `json` feature adds one crate (`tracing-serde`). It gives log shippers,
  the Collector's `filelogreceiver` and `journaldreceiver` among them, structured fields instead
  of text to parse.
- Do not add OTLP log export now. In Rust it is stable, but it brings an exporter thread, a heap
  allocation per record, outgoing connections and credentials. goethite writes few logs: per-query
  data goes to the query log, not to `tracing`.
- If it is ever added, it is one `tracing-subscriber` layer (`opentelemetry-appender-tracing`)
  behind a cargo feature, off by default.

**Traces: no OpenTelemetry tracing for 1.0. Add `tracing` spans on the slow paths first.**

- Add spans with the existing `tracing` crate (no new dependencies) where one operation fans out
  or waits:
  - recursion, one span per outgoing query;
  - DNSSEC chain fetching;
  - upstream retries and failover;
  - list refreshes;
  - Raft replication and API requests.

  Keep them off the cache-hit and blocked fast path. Spans make today's logs readable by giving
  log lines their context, and they keep a later OTel export a one-layer change
  (`tracing-opentelemetry`).
- Do not trace every query to OTLP:
  - Trace context cannot arrive over DNS, so each trace would stay inside goethite.
  - The query log already holds the per-query record.
  - The servers that do trace queries keep it experimental, off by default and limited to chosen
    queries.
  - The Rust traces SDK is Beta and still breaking.
- If operators ask for distributed traces (most plausible for the cluster and the API), add them
  opt-in:
  - a cargo feature and config that are off by default;
  - `tracing-opentelemetry` with OTLP over gRPC and `tls-ring`;
  - providers built after the sandbox is applied;
  - head sampling, plus a per-client or per-name condition modelled on PowerDNS's.

  Revisit once OTel Rust declares tracing stable (tracking issue
  [#977](https://github.com/open-telemetry/opentelemetry-rust/issues/977), open).
- A better fit for home-lab users may be on-demand tracing of a single query through the API:
  resolve one name and return each step (policy, filter decision, cache, upstream or recursion
  steps, DNSSEC). It is a candidate for the backlog, not part of this research.

**Do not:**

- put the OTel metrics SDK on the per-query path;
- enable `reqwest-rustls` (it brings aws-lc-rs);
- make push the default or only path;
- implement the EDNS `TRACEPARENT` option before it has an IANA code.

## goethite today

- **Metrics:**
  - [`crates/goethite/src/metrics.rs`](../crates/goethite/src/metrics.rs) renders the Prometheus
    text format by hand, with no client library.
  - Per-query counters are a fixed 2-D array of `AtomicU64` (outcome × protocol), a 14-bucket
    latency histogram and a sum, all updated with `Ordering::Relaxed`. Everything else is read
    from its owner at scrape time.
  - The endpoint is `GET /metrics` on the API listener, with the bearer token once one is set
    ([API docs](../site/src/content/docs/api.md#metrics)).
  - [ADR 0007](adr/0007-query-log.md) records the choice of no client library.
- **Logs:** `tracing` and `tracing-subscriber` (`fmt`, `env-filter`) write human-readable text to
  stderr, which journald reads under systemd. There are no spans. A JSON format is a P2 item in
  the [backlog](BACKLOG.md).
- **Per-query record:** the query log's `LogEvent`
  ([`crates/goethite-store/src/querylog.rs`](../crates/goethite-store/src/querylog.rs)) holds:
  - time, client, protocol, name, query type and rcode;
  - outcome, upstream, the matched rule, the client ID and the group;
  - elapsed time.

  It is queued with `try_send` and dropped, and counted, when the queue is full
  ([ADR 0007](adr/0007-query-log.md)).
- **Performance baseline:** on an Apple M3 Pro, the criterion bench `resolve/cached answer` takes
  385–403 ns. dnsperf measured a p50 of 43–44 µs end to end on the same machine
  ([bench/README.md](../bench/README.md)).
- **Sandbox:** Landlock and seccomp are applied "before starting any thread". Outgoing TCP is not
  restricted, and Landlock rules for it are a listed alternative
  ([ADR 0032](adr/0032-sandbox.md)).

## OpenTelemetry Rust today

**Versions** (crates.io, 2026-10-10):

| Crate | Latest | MSRV | License |
| --- | --- | --- | --- |
| [`opentelemetry`](https://crates.io/crates/opentelemetry) | 0.33.1 (2026-10-09) | 1.75.0 | Apache-2.0 |
| [`opentelemetry_sdk`](https://crates.io/crates/opentelemetry_sdk) | 0.33.1 (2026-10-09) | 1.75.0 | Apache-2.0 |
| [`opentelemetry-otlp`](https://crates.io/crates/opentelemetry-otlp) | 0.33.1 (2026-10-09) | 1.75.0 | Apache-2.0 |
| [`opentelemetry-appender-tracing`](https://crates.io/crates/opentelemetry-appender-tracing) | 0.33.1 (2026-10-09) | 1.75.0 | Apache-2.0 |
| [`opentelemetry-prometheus`](https://crates.io/crates/opentelemetry-prometheus) | 0.33.1 (2026-10-09) | 1.81.0 | Apache-2.0 |
| [`tracing-opentelemetry`](https://crates.io/crates/tracing-opentelemetry) | 0.34.0 (2026-09-23) | 1.75.0 | MIT |

**Stability as the project states it:**

- The README's status table
  ([OTEL@372ebbc README](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/README.md#L30-L50))
  marks these Stable:
  - Logs: API, SDK, OTLP exporter and Appender-Tracing.
  - Metrics: API, SDK and OTLP exporter.
- It marks these not yet stable:
  - Metrics-Prometheus exporter, traces API, SDK and OTLP exporter, context and propagators: Beta.
  - Baggage: RC.
- The two OTLP exporters became stable only in the latest release. The 0.33.1 changelog says:
  "Declare the OTLP exporters for Logs and Metrics stable after the 0.33.0 release-candidate
  period. Tracing remains in beta."
  ([`opentelemetry-otlp/CHANGELOG.md`](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/CHANGELOG.md#L5-L10);
  [release notes 0.33.1](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/release_0.33.1.md)).
- The 0.33 release notes say: "The Logs and Metrics API and SDK remain stable with no breaking
  changes. The Distributed Tracing API, SDK, and OTLP exporter remain pre-stable, and this release
  includes intentional breaking changes in that area"
  ([release notes 0.33](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/release_0.33.md)).
  The 0.32 notes say the same about logs and metrics
  ([release notes 0.32](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/release_0.32.md)).
- The traces stabilization tracker, issue
  [#977](https://github.com/open-telemetry/opentelemetry-rust/issues/977), has been open since
  2023-02-28. A comment from 2026-09-28 says "All three tracing components remain Beta".
- Metrics exemplars, the link from a metric data point to a trace, are not collected. Issue
  [#3369](https://github.com/open-telemetry/opentelemetry-rust/issues/3369), "Implement exemplar
  collection for metrics (required for stable)", is open. At `372ebbc`, every aggregation in
  `opentelemetry-sdk/src/metrics/internal/` builds its data points with an empty exemplar list
  (21 occurrences), and no exemplar filter or reservoir exists.

**Versioning and cadence:**

- The policy promises SemVer and that new signals arrive behind cargo features
  ([VERSIONING.md](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/VERSIONING.md)).
- The crates are still 0.x. For Cargo, every 0.x minor release is a new incompatible version, so
  `opentelemetry`, the SDK, the exporter and the bridges have to be upgraded together.
- Minor releases ([crates.io](https://crates.io/crates/opentelemetry/versions)):
  - 2025: 0.28.0 (02-10), 0.29.0 (03-22), 0.30.0 (05-23) and 0.31.0 (09-25).
  - 2026: 0.32.0 (05-08) and 0.33.0 (09-18).

  That is six in 20 months, with the gaps growing.
- In the 0.33.0 changelogs, the OTLP exporter marks 15 entries "Breaking". The API and SDK
  changelogs mark none
  ([`opentelemetry-otlp/CHANGELOG.md`](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/CHANGELOG.md#L12)).
- `tracing-opentelemetry` 0.34.0 depends on `opentelemetry` 0.33. Its README says its version
  numbers "are **not** synchronized" with the OTel crates
  ([README at 0.34.0](https://docs.rs/crate/tracing-opentelemetry/0.34.0/source/README.md)).
  On crates.io it followed `opentelemetry` 0.31 after 5 days, 0.32 after 10 days and 0.33 after
  5 days ([versions](https://crates.io/crates/tracing-opentelemetry/versions)).

**MSRV:** 1.75. The policy keeps it within the current stable and the three minor releases before
it
([README](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/README.md#L144-L155)).
goethite requires 1.99 (`Cargo.toml`), so this is no constraint.

**How the project wants `tracing` used:**

- Its traces guide is marked "Work-In-Progress". It says that "[`tracing`] should be used for
  logs and events, not for OpenTelemetry spans".
- New code should prefer the OTel tracing API. `tracing-opentelemetry` is "maintained outside the
  OpenTelemetry project".
- For internal spans, the bridge's result is "nearly identical" to the OTel API.

([docs/traces.md](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/traces.md#L1-L59))

## Dependency cost

**Method.**

- A throwaway crate carries all of goethite's external `[workspace.dependencies]` and a copy of
  goethite's `Cargo.lock`, so the shared crates resolve to the same versions.
- Each setup below adds the OTel crates to it. The count is the packages in
  `cargo tree -e normal,build --target x86_64-unknown-linux-gnu` that the baseline does not have.
  The baseline has 276 packages; goethite's own workspace has 277.
- The features come from the
  [`opentelemetry-otlp` manifest](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/Cargo.toml#L64-L107).
  Its default is `http-proto` with `reqwest-blocking-client`.

| Setup (traces, metrics and logs SDKs unless noted) | New crates | TLS |
| --- | --- | --- |
| OTLP over HTTP/protobuf, crate defaults (blocking reqwest) | 14 | none |
| Same, metrics only (`http-proto` still turns on the trace feature) | 14 | none |
| OTLP/HTTP with `reqwest-rustls` for HTTPS | 25 | rustls with **aws-lc-rs** |
| OTLP over gRPC (`grpc-tonic`, `tls-ring`, `tls-webpki-roots`) | 18 | rustls with ring (already in goethite) |
| OTLP/HTTP with `hyper-client` (needs the experimental async-runtime processors) | 13 | none built in |
| `reqwest-rustls` plus `tracing-opentelemetry` and `opentelemetry-appender-tracing` | 28 | aws-lc-rs |
| For comparison: `opentelemetry-prometheus` (pull, metrics only) | 4 | none |
| For comparison: `prometheus-client` 0.25.1 (the Prometheus project's Rust client) | 3 | none |
| For comparison: `tracing-subscriber` feature `json` | 1 (`tracing-serde`) | none |

**What the setups add:**

- The default HTTP setup adds `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-http`,
  `opentelemetry-otlp`, `opentelemetry-proto`, `prost`, `prost-derive`, `reqwest`, `tower-http`
  and `async-trait`. It also adds `rand` 0.9, `rand_core` 0.9, `rand_chacha` 0.9 and `getrandom`
  0.3, while goethite uses `rand` 0.10.
- gRPC replaces `reqwest` and `tower-http` with `tonic`, `tonic-prost`, `tonic-types`,
  `prost-types`, `hyper-timeout`, `tokio-stream` and `base64` 0.22.

**TLS:**

- `opentelemetry-otlp`'s `reqwest-rustls` turns on `opentelemetry-http/reqwest-rustls`, which is
  `reqwest/rustls`
  ([opentelemetry-http manifest](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-http/Cargo.toml#L18)).
- In reqwest 0.13.5, `rustls = ["__rustls-aws-lc-rs", …]`. The alternative, `rustls-no-provider`,
  is not exposed through OTel's features
  ([reqwest v0.13.5 Cargo.toml](https://github.com/seanmonstar/reqwest/blob/v0.13.5/Cargo.toml#L41-L46)).
- With `reqwest-rustls`, the measured tree gains `aws-lc-rs`, `aws-lc-sys`, `cmake`, `jobserver`,
  `fs_extra`, `dunce`, `pkg-config`, `hyper-rustls`, `rustls-platform-verifier`,
  `rustls-native-certs` and `openssl-probe`.
- gRPC with `tls-ring` (`tonic/tls-ring`) uses the rustls and ring goethite already has; no
  aws-lc crate appears.
- The HTTP transport can be replaced. `opentelemetry_http::HttpClient` is a public trait with one
  method, and `HyperClient::new` takes any connector
  ([opentelemetry-http lib.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-http/src/lib.rs#L138-L147)).
  goethite could therefore send OTLP/HTTP over its own hyper and rustls with ring. The exporter's
  manifest says not to enable the async clients "for the default SDK processors/readers"
  ([Cargo.toml](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/Cargo.toml#L99-L103)),
  so this needs the experimental async-runtime processors or a blocking client goethite writes
  itself.

**`cargo deny`:**

- `cargo deny check` (0.20.2) was run with goethite's `deny.toml` on the union of the HTTPS,
  gRPC and tracing-bridge setups. Licenses, advisories, bans and sources all pass.
- All the OTel crates are Apache-2.0. `tonic`, `tracing-opentelemetry` and `tower-http` are MIT.
- `aws-lc-sys`'s expression (ISC, Apache-2.0, MIT, BSD-3-Clause and alternatives) is satisfiable
  from the allow-list.
- It adds new duplicate-version warnings: `base64` (0.22 for tonic beside 0.23), `rand_chacha`,
  and a third version each of `rand`, `rand_core` and `getrandom`.

**Threads:** each signal's default processor or reader runs on a dedicated OS thread, started when
the provider is built:

- traces: `OpenTelemetry.Traces.BatchProcessor`;
- logs: `OpenTelemetry.Logs.BatchProcessor`;
- metrics: `OpenTelemetry.Metrics.PeriodicReader`.

([span_processor.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/trace/span_processor.rs#L570-L572),
[batch_log_processor.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/logs/batch_log_processor.rs#L470),
[periodic_reader.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/metrics/periodic_reader.rs#L180))

The batch processors call `.expect(…)` on the spawn, so they panic if the OS refuses a thread
([span_processor.rs L687](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/trace/span_processor.rs#L687),
[batch_log_processor.rs L633](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/logs/batch_log_processor.rs#L633)).
Landlock confines only threads started after it is applied ([ADR 0032](adr/0032-sandbox.md)). The
providers would therefore have to be built after the sandbox.

## Hot-path cost

**What the SDK does per measurement** (`opentelemetry_sdk` at `372ebbc`):

- **Attribute lookup.** Each instrument keeps its attribute sets in
  `RwLock<HashMap<Vec<KeyValue>, Arc<TrackerEntry>>>`, using std's default hasher.
  `ValueMap::measure` works like this:
  - With no attributes, it updates a dedicated tracker directly.
  - Otherwise it takes the read lock and looks up the attribute slice as given.
  - On a miss, it sorts and de-duplicates the attributes into a newly allocated `Vec` and looks
    again.
  - Only for a new set does it take the write lock.

  ([internal/mod.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/metrics/internal/mod.rs#L82-L191),
  [`sort_and_dedup`](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/metrics/internal/mod.rs#L427-L436))
- **Allocation.** The project's guide says that passing attributes in a consistent order, as an
  array slice, avoids allocations on the measurement path
  ([docs/metrics.md](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/metrics.md#L130-L182)).
- **Counters** add to an atomic in the tracker.
- **Histograms** find the bucket with a binary search, then update the tracker's
  `Mutex<Buckets>`
  ([histogram.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/metrics/internal/histogram.rs#L19-L31)).
- **Bound instruments** (`Counter::bind` and the others) resolve the tracker once, and later
  calls write to it directly. They need the `experimental_metrics_bound_instruments` feature, and
  "The API may change in future releases"
  ([docs/metrics.md](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/docs/metrics.md#L245-L345)).

**The project's own benchmark** (Apple M4 Max, 3 attributes;
[benches/bound_instruments.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/benches/bound_instruments.rs#L5-L26)):

| Operation | Unbound | Bound |
| --- | --- | --- |
| `Counter::add` | 50.20 ns | 1.92 ns |
| `Histogram::record` | 60.15 ns | 6.61 ns |

The project publishes a
[benchmark dashboard](https://open-telemetry.github.io/opentelemetry-rust/dev/bench/).

**Measured against goethite's observer.**

- **Harness.** A throwaway harness copies goethite's `Metrics::observe`: a counter in the
  outcome × protocol array, a histogram bucket and a sum, all relaxed. It compares that with OTel
  doing the same:
  - a `u64` counter with the attributes `outcome` and `protocol`;
  - an `f64` histogram with goethite's 14 bucket bounds and no attributes;
  - the same two instruments bound once at start.
- **Setup.** `opentelemetry_sdk` 0.33.1 with a `ManualReader` (no export), on an Apple M3 Pro
  running macOS. Release build, Rust 1.98.1, 5,000,000 observations per thread. Every attribute
  combination was warmed up first.
- **Allocations.** A counting global allocator saw no heap allocation from metric updates in any
  of the three.
- **Results.** Five runs on a machine that was not idle:

| Per-query update | 1 thread, ns per observation | Allocations |
| --- | --- | --- |
| goethite, relaxed atomics | 2.7–5.3 | 0 |
| OTel, unbound counter + histogram | 83–121 | 0 |
| OTel, bound (experimental) | 13–21 | 0 |

- **Under contention.** With 4 and 8 threads updating the same counters, every design was
  dominated by cache-line contention. Per observation, per thread, at 8 threads: goethite
  0.53–0.64 µs, OTel unbound 2.25–2.33 µs, OTel bound 0.69 µs. That is a worst case, not a DNS
  workload; it shows that the unbound path's lock and mutex cost more than plain atomics when
  cores collide.
- **For scale:** goethite's whole in-process cached answer is 385–403 ns on the same CPU model
  ([bench/README.md](../bench/README.md)). The unbound OTel update would add about 20–30% to that,
  and about 0.2% to the 44 µs end-to-end p50. The cost is real but not fatal; it buys nothing that
  `/metrics` lacks today.

<details>
<summary>The harness (throwaway; not part of goethite)</summary>

```rust
// Cargo: opentelemetry = { version = "=0.33.1", default-features = false, features = ["metrics"] }
//        opentelemetry_sdk = { version = "=0.33.1", default-features = false, features = ["metrics",
//            "experimental_metrics_custom_reader", "experimental_metrics_bound_instruments"] }
const BUCKETS_US: [u64; 14] = [100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000,
    100_000, 250_000, 500_000, 1_000_000, 2_500_000];
// goethite: copy of Metrics::observe (7 outcomes x 6 protocols, 15 latency counters, a sum).
fn observe(&self, o: usize, p: usize, micros: u64) {
    if let Some(c) = self.queries.get(o).and_then(|r| r.get(p)) { c.fetch_add(1, Relaxed); }
    let b = BUCKETS_US.iter().position(|x| micros <= *x).unwrap_or(BUCKETS_US.len());
    if let Some(c) = self.latency.get(b) { c.fetch_add(1, Relaxed); }
    self.latency_sum_us.fetch_add(micros, Relaxed);
}
// OTel unbound:
counter.add(1, &[KeyValue::new("outcome", OUTCOMES[o]), KeyValue::new("protocol", PROTOCOLS[p])]);
hist.record(micros as f64 / 1e6, &[]);
// OTel bound: bound[o][p].add(1); bound_hist.record(micros as f64 / 1e6);
// Each closure runs 5,000,000 times per thread under std::thread::scope; time = wall / iterations.
```

</details>

## Prometheus interop

**`opentelemetry-prometheus` (Rust exporter):**

- Its history:
  - At `v0.31.0` the README said the crate was "no longer recommended for use", "Version 0.29
    will be the final release", and to use OTLP
    ([README at v0.31.0](https://github.com/open-telemetry/opentelemetry-rust/blob/v0.31.0/opentelemetry-prometheus/README.md)).
  - Issue [#3288](https://github.com/open-telemetry/opentelemetry-rust/issues/3288), "Un-deprecate
    Prometheus", was closed on 2026-05-07.
  - 0.32.0 then shipped with "Un-deprecate `opentelemetry-prometheus`"
    ([CHANGELOG](https://github.com/open-telemetry/opentelemetry-rust/blob/opentelemetry-prometheus-0.33.1/opentelemetry-prometheus/CHANGELOG.md)).
- At 0.33.1, the README still says "For new projects, consider using the opentelemetry-otlp crate
  instead"
  ([README](https://github.com/open-telemetry/opentelemetry-rust/blob/opentelemetry-prometheus-0.33.1/opentelemetry-prometheus/README.md)).
  The status table marks it Beta.
- It depends on the tikv `prometheus` 0.14 crate and on the SDK feature
  `experimental_metrics_custom_reader`
  ([Cargo.toml](https://github.com/open-telemetry/opentelemetry-rust/blob/opentelemetry-prometheus-0.33.1/opentelemetry-prometheus/Cargo.toml)).

**Prometheus's OTLP receiver**
([CHANGELOG v3.15.0](https://github.com/prometheus/prometheus/blob/v3.15.0/CHANGELOG.md)):

- **History:**
  - 2.47.0 (2023-09-06) added it as experimental, behind `--enable-feature=otlp-write-receiver`.
    The docs of that version said: "Prometheus is best used as a Pull based system, and staleness,
    `up` metric, and other Pull enabled features won't work when you push OTLP metrics"
    ([feature_flags.md at v2.47.0](https://github.com/prometheus/prometheus/blob/v2.47.0/docs/feature_flags.md)).
  - 3.0.0 (2024-11-14) moved it to the flag `--web.enable-otlp-receiver`, default `false`
    ([command line at v3.15.0](https://github.com/prometheus/prometheus/blob/v3.15.0/docs/command-line/prometheus.md)).
- **Stability:** the stability page lists "OTLP receiver endpoint" as stable
  ([stability.md](https://github.com/prometheus/prometheus/blob/v3.15.0/docs/stability.md)).
- **Delta temporality** needs `otlp-deltatocumulative` or `otlp-native-delta-ingestion`. Native
  delta support is "in a very early stage"
  ([feature_flags.md at v3.15.0](https://github.com/prometheus/prometheus/blob/v3.15.0/docs/feature_flags.md)).
- **Prometheus's OTel guide**
  ([guide at 605cf81](https://github.com/prometheus/docs/blob/605cf81fefc2e8e91f8ba89bb1555ae52a43a318/docs/guides/opentelemetry.md)):
  - The receiver accepts HTTP only, at `/api/v1/otlp/v1/metrics`.
  - It is off by default "because Prometheus can work without any authentication, so it would not
    be safe to accept incoming traffic unless explicitly configured".

**OTel Collector contrib v0.162.0:**

- **`prometheusreceiver`:** beta for metrics. Its README calls it "a drop-in replacement for
  getting Prometheus to scrape your services" that "supports the full set of Prometheus
  configuration in `scrape_config`"
  ([metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.162.0/receiver/prometheusreceiver/metadata.yaml),
  [README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.162.0/receiver/prometheusreceiver/README.md)).
  The full `scrape_config` includes the `authorization` block with `credentials_file`, which
  goethite's docs already use.
- **Tested against goethite, 2026-10-10.** The signed v0.5.0 release binary
  (`aarch64-unknown-linux-gnu`, checked against `SHA256SUMS`) ran in one container with
  `token_sha256` set. `otel/opentelemetry-collector-contrib:0.162.0` ran in another, with a
  `prometheus` receiver, the `scrape_config` from the [API docs](../site/src/content/docs/api.md#metrics)
  and the `debug` exporter. After four queries (two forwarded, one cached, one blocked):
  - The scrape with the right token succeeded (`up` 1). All 23 `goethite_*` families arrived in
    OTel's data model: counters as `Sum`, gauges as `Gauge` and
    `goethite_query_duration_seconds` as a `Histogram` with goethite's 14 bounds and `Count: 4`.
    Labels such as `outcome` and `protocol` became attributes.
  - A second job with a wrong token got `401 Unauthorized` on every scrape (`up` 0), and so did a
    plain request with no token.

  No change to goethite was needed, and nothing in it knows about OTel.
- **`journaldreceiver`:** alpha for logs, not on darwin or windows. It "requires the journalctl
  binary"
  ([README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.162.0/receiver/journaldreceiver/README.md)).
- **`filelogreceiver`:** beta for logs
  ([metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.162.0/receiver/filelogreceiver/metadata.yaml)).
- **What the levels mean:** alpha is for "limited non-critical workloads". Beta has stable
  configuration, but "there might be breaking changes between releases"
  ([component-stability.md](https://github.com/open-telemetry/opentelemetry-collector/blob/v0.162.0/docs/component-stability.md)).

**The compatibility spec:** "Prometheus and OpenMetrics Compatibility" has status Mixed. Counters,
gauges, classic histograms, summaries and metadata are stable in both directions
([spec v1.61.0](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.61.0/specification/compatibility/prometheus_and_openmetrics.md)).
goethite exposes only counters, gauges and one classic histogram, so everything it exposes falls
in the stable part.

## DNS semantic conventions

- **The DNS page has status Development and covers metrics only**
  ([docs/dns at v1.44.0](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/docs/dns/README.md)).
- **Two attributes, both Development**
  ([registry.yaml](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/dns/registry.yaml)):
  - `dns.question.name`: "The name being queried", "without any additional normalization".
  - `dns.answers`: "IPv4 or IPv6 addresses resolved during DNS lookup".
- **One metric, Development:** `dns.lookup.duration`, a histogram in seconds of the "time taken to
  perform a DNS lookup". `dns.question.name` is required on it, and `error.type` uses `getaddrinfo`
  codes such as `host_not_found`
  ([metrics.yaml](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/dns/metrics.yaml)).
  This describes a client resolving a name, not a server answering one.
- **Open issues:**
  - [#2432](https://github.com/open-telemetry/semantic-conventions/issues/2432), "Finish
    documenting DNS namespace" (open since 2025-06-25), proposes `dns.question.type`,
    `dns.response_code`, and server metrics and spans, citing CoreDNS's metrics.
  - [#3899](https://github.com/open-telemetry/semantic-conventions/issues/3899) (open) asks to make
    `dns.question.name` opt-in on the metric. OTel's eBPF instrumentation already did, "because of
    unbounded cardinality issues".
- **The generic attributes goethite would use are stable:** `client.address`, `server.address`,
  `server.port`, `network.transport`, `network.protocol.name` and `error.type`
  ([client](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/client/registry.yaml),
  [server](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/server/registry.yaml),
  [network](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/network/registry.yaml),
  [error](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/model/error/registry.yaml)).

## What other DNS servers chose

| Server | Prometheus | OTel / OTLP | Per-query tracing and how cost is limited |
| --- | --- | --- | --- |
| CoreDNS v1.14.7 | `prometheus` plugin, `/metrics` on `localhost:9153` | None; an OTel plugin was turned down | `trace` plugin, Zipkin or Datadog only, sampled by `every N` (default 1) |
| PowerDNS Recursor 5.4.7 | `/metrics` on the built-in web server since 4.2.0 (2019); the web server is off by default | OTel trace protobuf inside its own protobuf logging, since 5.3.0; no OTLP exporter | Experimental and off by default; since 5.4.0 only for queries matching a condition (client subnets, then names, types) |
| dnsdist 2.1.2 | `/metrics` since 1.3.3 (2018) | OTel trace data in protobuf `RemoteLogger` messages since 2.1.0, experimental | A global switch, then a `SetTrace` action chosen by rules |
| Unbound 1.26.1 | No; `contrib/metrics.awk` and the third-party `unbound_exporter` | None | None (dnstap) |
| Knot Resolver 6.5.0 | Manager API `/metrics/prometheus` | None | None |
| BIND 9.20.29 | No; the statistics channel serves XML or JSON, and a third-party exporter exists | None | None (dnstap) |
| Blocky v0.35.0 | `prometheus.enable` (off by default), `/metrics` | None | None |
| Technitium v15.6 | Since v15.0 (2026-04-25), experimental, `GET /api/dashboard/metrics/text` with a bearer token | None | None |

**CoreDNS:**

- Sources: the
  [metrics plugin](https://github.com/coredns/coredns/blob/v1.14.7/plugin/metrics/README.md) and
  the [trace plugin](https://github.com/coredns/coredns/blob/v1.14.7/plugin/trace/README.md).
  The trace plugin is "OpenTracing-based" and says "Currently only `zipkin` and `datadog` are
  supported".
- PR [#5777](https://github.com/coredns/coredns/pull/5777), an OTel plugin, was closed unmerged on
  2023-03-13. On it, a code owner of the metrics plugin wrote: "I'm not sure I want opentelemetry
  in CoreDNS. I'd rather go with a lighter weight tracing library. OTel brings in a lot of excess
  baggage. Perhaps this would be more appropriate as an external plugin."
  ([comment](https://github.com/coredns/coredns/pull/5777#issuecomment-1327205020),
  [CODEOWNERS](https://github.com/coredns/coredns/blob/v1.14.7/CODEOWNERS)).

**PowerDNS Recursor:**

- [metrics.rst](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/pdns/recursordist/docs/metrics.rst#L94-L105),
  [4.2 changelog](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/pdns/recursordist/docs/changelog/4.2.rst).
- What it does: "Recursor will set the `openTelemetryData` field of `dnsmessage.proto` messages
  generated to contain OpenTelemetry Traces, encoded as Protobuf data". Since 5.4.0, "Queries
  coming from an IP not matching any of the mentioned subnets will not generate OpenTelemetry
  Trace information"
  ([performance.rst](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/pdns/recursordist/docs/performance.rst#L411-L497),
  [dnsmessage.proto](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/pdns/dnsmessage.proto#L195-L198)).
- `event_trace_enabled` defaults to 0
  ([table.py](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/pdns/recursordist/rec-rust-lib/table.py#L1006)).
- Forwarding the traces to a collector relies on a contrib Python script that POSTs the bytes
  ([ProtobufLogger.py](https://github.com/PowerDNS/pdns/blob/rec-5.4.7/contrib/ProtobufLogger.py#L91-L94)).

**dnsdist:**

- [ottrace.rst](https://github.com/PowerDNS/pdns/blob/dnsdist-2.1.2/pdns/dnsdistdist/docs/reference/ottrace.rst),
  [webserver.rst](https://github.com/PowerDNS/pdns/blob/dnsdist-2.1.2/pdns/dnsdistdist/docs/guides/webserver.rst#L163).
- "Tracing uses more memory and CPU than usual query processing and it is recommended to enable
  tracing only for certain queries using specific selectors."
- 2.1.0-rc1 included "Reduce the cost of disabled OpenTelemetry tracing" and "Fix a crash when
  OpenTelemetry tracing is enabled"
  ([changelog](https://github.com/PowerDNS/pdns/blob/3fe6ea92797000a07c06d24193f2549a26c1ad43/pdns/dnsdistdist/docs/changelog.rst)).

**Unbound:**

- Prometheus support, issue [#352](https://github.com/NLnetLabs/unbound/issues/352), has been open
  since 2020
  ([metrics.awk](https://github.com/NLnetLabs/unbound/blob/release-1.26.1/contrib/metrics.awk)).

**Knot Resolver:**

- [config-monitoring-stats.rst](https://github.com/CZ-NIC/knot-resolver/blob/v6.5.0/doc/user/config-monitoring-stats.rst#L34-L50).
  This is the GitHub mirror; the canonical repository is on gitlab.nic.cz.

**BIND:**

- The ARM warns that the statistics channel "locks various subsystems in named, which could slow
  down query processing if statistics data is requested too often"
  ([reference.rst](https://github.com/isc-projects/bind9/blob/v9.20.29/doc/arm/reference.rst#L5944-L6000)).
- Issue [#699](https://gitlab.isc.org/isc-projects/bind9/-/issues/699) (Prometheus) was closed on
  2020-11-12, pointing to the third-party `bind_exporter`.

**Blocky:**

- [configuration.md](https://github.com/0xERR0R/blocky/blob/v0.35.0/docs/configuration.md#L1067-L1076).

**Technitium:**

- [CHANGELOG](https://github.com/TechnitiumSoftware/DnsServer/blob/v15.6.0/CHANGELOG.md) and
  [APIDOCS.md](https://github.com/TechnitiumSoftware/DnsServer/blob/v15.6.0/APIDOCS.md).

**The "None" cells:**

- For Unbound, Knot Resolver, BIND, Blocky and Technitium, the OTel column rests on their docs,
  dependency manifests and issue searches. It is not a full code audit.
- The competitor research ([competitor-features.md](competitor-features.md)) found no Prometheus
  endpoint in AdGuard Home, Pi-hole or Numa.

## Tracing a DNS resolver

**Where spans would help goethite:**

- **Recursion.** One client query can fan out into many outgoing queries: delegations, name
  server addresses, DS and DNSKEY fetches for DNSSEC.
  - Today only totals exist (`RecursorStats`: sent, TCP, timeouts, failures, secure, insecure,
    bogus; [`recurse.rs`](../crates/goethite-resolver/src/recurse.rs)), plus the query's total
    elapsed time in the query log.
  - A span per outgoing query is the one thing that would show where a slow recursive answer
    spent its time.
- **Forwarding.** Spans around upstream retries and failover would answer the same question for
  forwarded queries.
- **Cluster.** Raft replication and the member connections are the only place a goethite trace
  crosses processes. openraft 0.9.25 already carries 117 `#[tracing::instrument]` attributes in
  its source (counted in the crate from crates.io), so a subscriber that records spans sees them
  without goethite adding any.
- **API.** Requests are few, and their spans are cheap.
- **The fast path** (cache hit, block, local record) is where the cost lands on every query. A
  span there would add little beyond the query log's `LogEvent`.

**Trace context in DNS:** there is no standard.

- The draft "Communicating Distributed Trace IDs in EDNS" (Moerbeek, van Dijk, Lexis; PowerDNS)
  exists only on GitHub ([repository](https://github.com/PowerDNS/draft-edns-otel-trace-ids),
  HEAD `2949b33`, 2026-02-23). It is marked `submissiontype: independent` and has option code
  "TBD1".
- The IETF Datatracker has no such document; searches on 2026-10-10 for `otel`, `traceparent`
  and `edns-trace` found none.
- The IANA EDNS0 option registry has no `TRACEPARENT` entry
  ([registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)).
  PowerDNS uses 65500, which is in the "Reserved for Local/Experimental Use" range.
- The Recursor (5.3.0 and later) and dnsdist (2.1.0 and later) implement it. dnsdist calls it
  "the experimental TRACEPARENT EDNS option". No implementation was found in the other six
  servers checked.

**How peers limit the cost** (sources in [What other DNS servers chose](#what-other-dns-servers-chose)):

- CoreDNS samples one query in N.
- PowerDNS keeps tracing off by default and, since Recursor 5.4, generates trace data only for
  queries matching configured client subnets and names.
- dnsdist recommends rules that select a few queries.

None of the servers checked traces and exports every query by default.

## Push or pull

**Prometheus:**

- The FAQ prefers pull because more monitoring instances can be started, a target that is down is
  easier to spot, and a target can be inspected in a browser. It adds that pull is "slightly
  better" and "should not be considered a major point"
  ([FAQ at 605cf81](https://github.com/prometheus/docs/blob/605cf81fefc2e8e91f8ba89bb1555ae52a43a318/docs/introduction/faq.md)).
- The Pushgateway guide says that "the only valid use case" is the outcome of a service-level
  batch job
  ([pushing.md](https://github.com/prometheus/docs/blob/605cf81fefc2e8e91f8ba89bb1555ae52a43a318/docs/practices/pushing.md)).

**OTLP exporter defaults** (spec v1.61.0,
[exporter.md](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.61.0/specification/protocol/exporter.md),
[sdk-environment-variables.md](https://github.com/open-telemetry/opentelemetry-specification/blob/v1.61.0/specification/configuration/sdk-environment-variables.md)):

- Endpoints: `http://localhost:4318` (HTTP) and `:4317` (gRPC).
- Timeout 10 s.
- Credentials through `OTEL_EXPORTER_OTLP_HEADERS`, or client certificates.
- Batch queues of 2048 spans or log records.
- Metric export every 60 s.

**What happens when the collector is down** (Rust SDK at `372ebbc`):

- `on_end` and `emit` use `try_send` into bounded channels and drop when they are full. The log
  processor first boxes a clone of each record
  ([batch_log_processor.rs L190](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/logs/batch_log_processor.rs#L190),
  [span_processor.rs L818](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/src/trace/span_processor.rs#L818)).
- Since 0.33.0, exports retry up to three times with backoff and jitter
  ([CHANGELOG](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/CHANGELOG.md#L12)).
  On the SDK's default threads, the retries wait with `std::thread::sleep`, which blocks the
  exporter's thread and not the caller
  ([retry.rs](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-otlp/src/retry.rs#L14-L27)).
- Since 0.33.1, failed metric exports are logged at ERROR
  ([SDK CHANGELOG](https://github.com/open-telemetry/opentelemetry-rust/blob/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/opentelemetry-sdk/CHANGELOG.md#L36-L39)).
- Metrics default to cumulative temporality, so a missed export loses resolution, not totals.
  That follows from what cumulative means; it was not tested.

**What a push would mean for goethite:**

- An outgoing connection from a sandboxed DNS server. It is allowed today, but would have to be
  in any future Landlock TCP-connect policy ([ADR 0032](adr/0032-sandbox.md)).
- A credential for the collector, stored in config or in the environment.
- A collector that has to be run and kept up, which most home labs do not have.
- An air-gapped site can run either model locally. Pull needs only the Prometheus server those
  users already have.
- `/metrics` stays on the API listener, behind the token, and adds no outgoing traffic.

## Not verified

- **Push from the Rust SDK.** What it does when gRPC (tonic) export runs without a tokio runtime
  is known only from a doc comment. Pushing from goethite to a real collector was not tried.
- **Per-span cost.** The cost of a `tracing` span with a `tracing-opentelemetry` layer was not
  measured. Only metric updates were.
- **The microbenchmark.** It ran on a busy development Mac, not on Linux or on a quiet machine.
  The ranges are wide for that reason, and the ratios matter more than the absolute numbers.
- **BIND issue #699.** The reason it was closed could not be read; GitLab needs a login for the
  notes. Only its status and date are confirmed.
- **No OTLP code in PowerDNS.** That PowerDNS has no OTLP client rests on its docs, which describe
  only the protobuf-logging path. The C++ source was not searched in full.
