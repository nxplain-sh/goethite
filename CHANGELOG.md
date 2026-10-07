# Changelog

All notable changes to goethite are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and goethite uses
[semantic versioning](https://semver.org/). Before 1.0, minor versions may change the
configuration format.

## [Unreleased]

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

[Unreleased]: https://github.com/nxplain-sh/goethite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nxplain-sh/goethite/releases/tag/v0.1.0
