# ADR 0007: Query log and statistics off the hot path, in the store

- **Status:** Accepted; the metrics are extended by [ADR 0040](0040-opentelemetry.md)
- **Date:** 2026-10-08

## Context

Phase 2 adds a query log, statistics and Prometheus metrics. Every answered query feeds them, at
up to hundreds of thousands of queries per second, and answering must never wait on the disk
(AGENTS.md: hot paths never block, no avoidable allocation per query). The log holds client
addresses, so its retention and size must be bounded, and turning it off or anonymizing clients
must be easy. The user chose the default: on, full client addresses, 7 days.

## Decision

- **Hot path:** the server reports every answered query to a `QueryObserver`. goethite's observer
  increments atomic metric counters and copies the query into a `LogEvent`. The event has no heap
  allocation of its own: the name goes into a fixed buffer, the client and group IDs are shared
  `Arc<str>`. It is queued on a bounded channel (16,384 events) with `try_send`. When the queue
  is full, the event is dropped and counted (`goethite_querylog_dropped_total`). Nothing waits.
- **Writer thread:** a dedicated thread drains the queue in batches of up to a second or 4,096
  events. It anonymizes clients if asked, updates the statistics, and writes the batch to the
  store's `querylog` table in one transaction. Every minute it prunes by age and by count and
  saves the statistics. It never waits on the queue: it empties it every 50 ms and sleeps in
  between. A writer blocked on the queue would make the next query wake it, which puts a system
  call and a context switch on the hot path; the first v0.2.0 dnsperf run showed it in the tail
  latency. At 50 ms, the queue holds over 300,000 queries a second.
- **Records** use a compact, versioned binary encoding (about 60 bytes plus strings). It is decoded
  with bounds checks and fuzzed (`decode_query_record`). Keys are microseconds since the epoch
  times 1024, so they sort by time and serve as page cursors.
- **Statistics** are hourly: counters per outcome, plus approximate top lists (names, blocked
  names, clients). A list is bounded at 10,000 keys by halving all counts when full, and each
  finished hour keeps its top 100. Hours are kept 30 days, are saved in the store and survive
  restarts. Reports merge hours in memory.
- **Search** scans the log backwards from a cursor, with filters (client, name substring, outcome,
  time). One request looks at no more than 100,000 entries and returns no more than 1,000.
- **Metrics** are rendered by hand in the Prometheus text format, without a client library, from
  the atomics and from component state (cache, upstreams, server counters, filter).

## Consequences

- Under overload the log loses entries rather than slowing DNS down. The loss is visible in the
  metrics.
- One redb file holds configuration and logs. Log writes are batched, so they rarely contend with
  configuration writes. A very busy node may want `max_entries` lower, or the log off.
- Top lists are approximate. Rare names may be missing from them; counts for frequent ones are
  close.
