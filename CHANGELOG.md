# Changelog

All notable changes to goethite are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and goethite uses
[semantic versioning](https://semver.org/). Before 1.0, minor versions may change the
configuration format.

## [Unreleased]

### Added

- **A Terraform and OpenTofu provider**, in its own repository
  ([nxplain-sh/terraform-provider-goethite](https://github.com/nxplain-sh/terraform-provider-goethite)):
  lists, rules, groups, clients, schedules and settings, generated from goethite's OpenAPI
  document. A new guide on the website explains how to use it.

### Changed

- The web UI has one theme, light, whatever the system prefers; the theme switch in its header
  is gone.

## [0.3.0] - 2026-10-08

Phase 3, v0.3 high availability.

### Added

- **Two-node clusters.** A `[cluster]` table makes a node the primary or the replica of a pair.
  The replica copies the primary's configuration over mutual TLS within moments of every change,
  and keeps resolving with its last copy while the primary is unreachable. `goethite cluster
  init` and `goethite cluster cert <node>` create the cluster's CA and node certificates; each
  node accepts only its configured peer.
- **Changes through either node.** The replica forwards configuration changes to the primary
  with the caller's identity and answers once it has the change itself; while the primary is
  unreachable, they are refused rather than lost. `GET /api/v1/cluster` (and `cluster` in
  `/api/v1/status`) reports both nodes, sync state and problems such as two primaries.
  `POST /api/v1/cluster/promote` and `/demote` change roles; a promoted role survives restarts.
- **Upgrades without dropping a query.** `SIGUSR2` (`systemctl kill --signal=SIGUSR2
  --kill-whom=main goethite`) starts the new binary and hands it the sockets and the store; the
  old process finishes its queries and exits, and stays in charge if the new one fails. systemd
  also keeps the sockets across restarts and crashes, so queries wait instead of being refused.
  The unit is now `Type=notify` and allows Unix sockets.
- **Fail open.** If the store cannot be opened, goethite runs on a temporary one in memory seeded
  from the config file; if the filter cannot be built it starts unfiltered; if checking a name
  fails, the query is answered unfiltered. Each case is reported in `problems` of
  `/api/v1/status`, in the TUI and web UI, and in the metrics (`goethite_degraded`,
  `goethite_filter_failures_total`). `[filter] on_failure = "closed"` refuses to start or
  answers SERVFAIL instead.
- **Cluster statistics.** `GET /api/v1/stats?scope=cluster` adds up both nodes' counts and
  merges their top lists, naming any node it could not ask. The TUI and the web UI show the
  cluster's statistics and state.
- **A floating IP.** `goethite vrrp`, run by the new `goethite-vrrp.service` beside goethite on
  both nodes, moves one IPv4 address (the `[vrrp]` table) to whichever node is healthy, with VRRP
  version 3: within 3.6 seconds when the holder fails, in under a second when it stops. It checks
  its node's DNS server every second, announces moves with gratuitous ARP, accepts announcements
  only from the configured peer on the same link, and interoperates with keepalived. It runs
  with `CAP_NET_ADMIN` only once its sockets are open; the DNS server still runs with no
  capabilities, and binds the floating IP before holding it (`IP_FREEBIND`).
- **Chaos tests** (`tests/chaos/`): two nodes and a client in network namespaces, with upgrades,
  crashes, a partition and a corrupt filter list under load; run weekly and on demand in CI.
- Fuzz targets `parse_vrrp` and `parse_netlink`.

### Changed

- In the API, the audit log's `actor.kind` and `action` are now open-ended strings
  (`x-extensible-enum`): new values (such as `replication` and `replicate`) can appear without a
  new API version, so clients should show unknown values as they are. Audit entries can name the
  cluster `node` a change came from.
- New config tables: `[cluster]` and `[vrrp]`, and `on_failure` in `[filter]`.

### Fixed

- A log line that could not be written, because nothing read goethite's standard error any more,
  made goethite panic: at startup it exited, and later the task that logged died, which could
  leave goethite unable to stop on SIGTERM. Lost log lines are now ignored.

### Security

- The cluster channel is TLS 1.3 with certificates in both directions from the cluster's own CA;
  each node accepts only its configured peer's name. Copied configurations are validated as a
  whole, versioned and audit-logged.
- The floating IP's privileges live in their own process and unit
  (`systemd-analyze security` 1.9); the DNS server's unit stays at 1.7.
- Two `unsafe` blocks, as `AGENTS.md` allows with a written justification, each in one function
  with a `SAFETY` comment: taking the sockets systemd passes by number (the binary), and the
  link-layer address for gratuitous ARP (`goethite-cluster`). The parsing and resolving crates
  still forbid `unsafe`.

## [0.2.0] - 2026-10-08

Control: per-client filtering, a query log and statistics, a REST API, a terminal UI and the start
of a web UI. Still pre-alpha.

### Added

- **Clients and groups.** Clients are identified by address or network (the longest prefix
  wins) and belong to a group. Each group picks its filter lists, can turn filtering off, and can
  enforce safe search. Clients not listed are in the default group.
- **Schedules.** A list can apply to a group only during weekly time windows in a time zone
  (overnight windows included), for example social media blocked on school nights.
- **Safe search** for Google, YouTube, Bing and DuckDuckGo: their names answer with a CNAME to the
  provider's safe-search host.
- **CNAME uncloaking.** An answer whose CNAME chain passes through a blocked name is blocked, so
  trackers disguised under a first-party name are caught. Blocked answers say which rule and
  list decided.
- **Configuration store.** Lists, custom rules, groups, clients, schedules and filtering settings
  live in an embedded database (redb) with revisions. Every change is validated as a whole and
  written in the same transaction as an audit entry (who, from where, before and after); the
  newest 100,000 entries are kept.
- **Query log**, on by default: 7 days and at most 1,000,000 entries, client addresses
  anonymizable to /24 and /56, searchable by name, client, answer and time. Logging never slows
  answers: entries are queued, and dropped and counted if the writer falls behind.
- **Statistics**: hourly counts by answer and the most frequent names, blocked names and
  clients, kept for 30 days.
- **REST API** at `/api/v1` for all of the above, plus status, pausing filtering (up to a week),
  refreshing lists, the query log, statistics and the audit log. Changes take `If-Match`
  revisions; errors are JSON with stable codes. It is described by an OpenAPI 3.1 document
  (`/api/v1/openapi.json`, `goethite openapi`), browsable on the website with Scalar. CI fails on
  breaking changes to `/api/v1`.
- **Admin token.** `goethite token` creates one; the config holds only its SHA-256 hash.
  Without a token the API answers loopback only. HTTPS with your own certificate is optional.
- **Prometheus metrics** at `/metrics`: queries by answer, cache, upstreams, filter, rate
  limiting and listener counters.
- **`goethite tui`**, a terminal UI over the API: dashboard, live query log, lists, clients and
  groups; pauses filtering and turns lists on and off.
- **Web UI** at `/` on the API's address: sign-in, a dashboard with queries per hour, top lists,
  upstreams and lists, and a live query log. It is embedded into the binary (build `web/` first)
  and can be turned off with `[api] web_ui = false`.
- **`goethite import`** applies the config file's `[filter]` table to the store again.
- Fuzz targets `parse_cidr`, `decode_query_record` and `request_checks`.

### Changed

- **The store, not the config file, now owns filtering.** On the first start the `[filter]`
  table seeds the store; after that, edits to it are reported in the log but not applied. Run
  `goethite import` to apply them, or use the API.
- New config tables: `[store]`, `[querylog]` and `[api]`. The API listens on `127.0.0.1:8053` by
  default.

### Security

- The API refuses requests a browser could be tricked into sending: without a token, only
  `localhost`, `127.0.0.1` and `[::1]` are answered (no DNS rebinding), and requests from other
  web sites are refused. Every response carries a strict Content Security Policy.
- The API limits connections (64), handshake and header time (10 s), bodies (1 MiB) and
  requests (30 s).

## [0.1.0] - 2026-10-07

The first release: a filtering, caching, forwarding DNS resolver for one node, hardened for
production on Linux. It is pre-alpha software: try it, but do not rely on it yet.

### Added

- **Listeners.** DNS over UDP and TCP (RFC 7766 framing) on one or more addresses. On Linux each
  address gets one `SO_REUSEPORT` UDP socket per CPU core. Every query is bounded: datagram size,
  queries in flight, TCP connections in total and per client, idle time, shutdown grace.
- **Forwarding** to the upstreams you configure, over DNS over TLS, DNS over HTTPS (HTTP/2) or
  plain DNS, in order with failover and a back-off for failing upstreams. Plain DNS upstreams get
  a fresh random source port per query, random IDs, 0x20 case randomization and exact question
  matching, and are retried over TCP when truncated. Certificates are checked against bundled
  Mozilla roots for an explicitly configured name.
- **Cache.** A sharded, bounded TTL cache with TTL clamps and negative caching (RFC 2308). Only
  the CNAME chain that answers the question is cached.
- **Filtering.** Hosts files, plain domain lists and the core AdGuard DNS syntax (`||x^`, `|x^`,
  `*.x`, `@@` exceptions), mixed freely, compiled into one FST with a Bloom prefilter: a million
  rules fit in about 6 MiB. Blocked names get `0.0.0.0` / `::`, NXDOMAIN or REFUSED. Lists come
  from local files or are downloaded over HTTPS, validated, kept on disk for offline starts and
  refreshed on a schedule. `SIGHUP` re-reads them. A new filter is swapped in atomically, without
  dropping queries.
- **DNS rebinding protection**, on by default: forwarded answers for public names lose private,
  loopback and link-local addresses, except below `lan`, `home.arpa`, `internal` and `local`.
- **Rate limiting** of UDP queries per client network, with truncated answers that send real
  clients to TCP. On by default.
- **Privilege dropping.** goethite binds its sockets, then switches to `server.user` when started
  as root, gives up every capability and sets `no_new_privs`. The hardened systemd unit
  `dist/systemd/goethite.service` runs it as a dynamic user in a tight sandbox.
- **`goethite check-config`** validates a config file and its filter lists without starting the
  server.
- Documentation site with install, configuration, filtering and security guides, a threat model
  and architecture decision records.
- Fuzz targets for every parser (`decode_query`, `decode_response`, `parse_name`, `parse_list`),
  criterion benchmarks, a dnsperf script, and CI with clippy, tests on amd64 and arm64,
  cargo-deny and cargo-audit.

[Unreleased]: https://github.com/nxplain-sh/goethite/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/nxplain-sh/goethite/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nxplain-sh/goethite/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nxplain-sh/goethite/releases/tag/v0.1.0
