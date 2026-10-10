---
title: Metrics and telemetry
description: Scrape goethite's metrics with Prometheus, or send them to an OpenTelemetry collector over OTLP.
---

goethite keeps its metrics with [OpenTelemetry](https://opentelemetry.io/). It offers them two
ways, and both can be on at once:

- **Pull:** Prometheus, or an OpenTelemetry Collector, scrapes `/metrics` on the API. This is on
  whenever the API is.
- **Push:** goethite sends them to an OpenTelemetry collector over OTLP/HTTP. This is off until
  `[telemetry] endpoint` is set.

Both carry the same metrics. Pushed, they keep OpenTelemetry's names, such as `goethite.queries`
and `goethite.query.duration`; at `/metrics` they have their Prometheus names, such as
`goethite_queries_total` and `goethite_query_duration_seconds`.

## What the metrics hold

- **Queries:** answered queries by outcome and protocol (`udp`, `tcp`, `dot`, `doh`, `doq`,
  `odoh`), and a latency histogram from 100 µs to 2.5 s.
- **Turned away:** rate-limited and refused queries, refused TCP connections, failed TLS
  handshakes, and rejected DNS over HTTPS requests.
- **Resolution:** the cache's size, hits and misses; each upstream's health; recursion's queries,
  timeouts, failures and DNSSEC results.
- **Filtering:** rules, enabled lists, whether protection is on or paused, and filtering failures.
- **The node:** the query log's dropped entries, whether the node is degraded, its version and
  start time.

They hold counts and states only, never a name that was looked up or a client's address. Those
stay in the [query log](../configuration/#querylog).

## Prometheus

See [REST API](../api/#metrics) for the scrape configuration. `/metrics` needs the admin token
once one is configured.

## Sending to a collector

```toml
[telemetry]
endpoint = "https://collector.example:4318"
headers_file = "/etc/goethite/otlp-headers"
interval = 60
```

**Sending.** goethite posts the metrics to `<endpoint>/v1/metrics` every `interval` seconds, and
once more when it stops.

**What identifies the node.** Each export carries `service.name` = `goethite` and
`service.version`. On a [cluster](../ha/) member it also carries `service.instance.id` = the node's
name.

**The headers file.** It holds the headers a collector or vendor asks for, one per line:

```text
# An API key, for example
Authorization: Bearer <key>
```

Make it readable by root only: goethite reads it, and `ca_file`, before it drops its privileges.
A private CA goes in `ca_file`.

A minimal OpenTelemetry Collector configuration to receive them:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug: {}
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

**The collector's name.** goethite resolves it through its own upstreams and
[local records](../local-records/), not `/etc/resolv.conf`: the system's resolver may be goethite
itself, and goethite's sandbox does not read that file. Use an address, or a name your upstreams
or a local record answer. A container or Kubernetes service name answers only through those.

**When the collector is down.**

- DNS is never affected. Exports run on a thread of their own and give up after 10 seconds,
  retries included. The next export sends the counts so far.
- goethite logs one warning when exports start failing, and one line when they work again.
- `goethite_telemetry_export_failures_total` counts the failed requests, retries included.

**Which processes export.** Only `goethite run` sends telemetry. `goethite witness` and
`goethite vrrp` log to standard error as before.
