# Changelog

All notable changes to goethite are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and goethite uses
[semantic versioning](https://semver.org/). Before 1.0, minor versions may change the
configuration format.

## [Unreleased]

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

[Unreleased]: https://github.com/nxplain-sh/goethite/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nxplain-sh/goethite/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nxplain-sh/goethite/releases/tag/v0.1.0
