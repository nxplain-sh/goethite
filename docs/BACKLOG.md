# Backlog

Work noticed during earlier phases that belongs to a later one. Per [`AGENTS.md`](../AGENTS.md),
we note these items here instead of building them early. Each item is tagged with its target phase.
When an item is picked up, move it into an issue or PR and delete it from this list.

## Phase 1: v0.1 core blocker

Phase 1's scope shipped in v0.1.0. These items came up along the way; they are candidates for
0.1.x releases or for Phase 2.

- **[P1] Raise the open file limit at startup.** Every UDP query in flight forwards over its own
  socket, so the default soft limit of 1024 can run out under load. The systemd unit sets
  `LimitNOFILE=65536`; goethite could raise its soft limit to the hard limit itself.
- **[P2] Users from the name service switch.** `server.user` is looked up in `/etc/passwd`
  only; accept a numeric `uid:gid` for users that live in LDAP or systemd-homed.
- **[P1] Config hot reload** via `arc-swap`, without dropping queries.
- **[P1] `bench/` directory** with criterion benches and dnsperf/resperf scripts, ahead of the
  first performance claim.
- **[P1, perf] Zero-allocation fast-path decoder** behind `DnsCodec`
  (see [ADR 0001](adr/0001-hickory-proto-behind-trait.md)). Only with a criterion bench that shows
  the win.
- **[P1] Revisit the UDP response size policy.** Re-check the 1232-byte EDNS default and the
  truncation behaviour against RFC 9715 and DNS flag day guidance when forwarding lands.
- **[P1] EDNS cookies (RFC 7873)** for client and upstream spoofing resistance.
- **[P1] Out-of-order TCP answers.** A TCP connection resolves its queries one at a time, so a
  slow forwarded query delays the ones pipelined behind it (RFC 7766 allows answering out of
  order).
- **[P2] Custom CA certificates for upstreams in the config**, for private resolvers or
  TLS-inspecting networks (`TlsRoots::Custom` exists in the library; see ADR 0003).
- **[later] Pipelined DoT.** A DoT connection carries one query at a time; RFC 7766 allows
  several in flight with out-of-order answers.
- **[P1] Less allocation per forwarded query.** Each exchange allocates a receive buffer and
  re-encodes records through hickory; a cache hit clones its records to count TTLs down. Measure
  with `bench/` before and after.
- **[P2] Cache statistics in metrics.** `Cache::stats` counts hits and misses; export them (and
  the entry count) once Prometheus metrics exist.
- **[later] Serve-stale and prefetch** (RFC 8767): answer from an expired entry while refreshing it
  in the background, and refresh popular entries shortly before they expire.
- **[later] Smarter eviction.** The cache evicts the oldest entry first. Compare S3-FIFO or LRU
  with the benches and a realistic query mix before changing it.
- **[P1] OPT in FORMERR/NOTIMP responses.** Header-only error responses omit the OPT record even
  when the query carried one (RFC 6891 §7). Only BADVERS includes it today.
- **[P1] SOA in negative answers.** NODATA for local names carries no SOA in the authority
  section, so clients cannot cache it negatively (RFC 2308). Needed once local rewrites are
  configurable.
- **[P1] Configurable local records and rewrites** replacing the hardcoded `goethite.test.` record
  (the "local rewrites" pipeline stage).
- **[P1] Rate-limit per-packet debug logs** (dropped and rejected messages) so a flood with
  `RUST_LOG=debug` cannot drown the log.
- **[P1] TCP per-connection memory.** Each connection can hold up to about 192 KiB of buffers
  (query, response, frame) at the 64 KiB message limit. Revisit together with RFC 7766
  out-of-order pipelining and a per-connection query limit.
- **[P1] Hosts entries with real addresses as rewrites.** `192.168.1.5 printer.lan` lines are
  skipped as unsupported; they belong with configurable local records.
- **[P2] More filter syntax:** `$important`, `$badfilter`, `$client`, `$dnstype`, `$denyallow`
  (with client groups), and internationalized names in lists (convert to punycode).
- **[later] Regular-expression rules.** They cannot live in the FST; they would need a separate,
  bounded matcher (e.g. a size-limited `regex-automata` DFA) run only after the FST.
- **[P1] Re-read the config file on SIGHUP**, not only the filter lists.
- **[P2] List status in the API:** last download time, result, rule counts and the reason a
  download was rejected, and a way to trigger an update now.
- **[later] Signed or hash-pinned lists**, for list sources that publish signatures.
- **[P1] Name parsing for filter lists.** `Name::from_str` only accepts host-style names (no
  escapes, no wildcards). Filter syntax needs wildcards and may need RFC 1035 escapes; extend the
  parser (and its `parse_name` fuzz target) rather than adding a second one.
- **[P1] TCP fairness under load.** Per-client limits exist, but many hosts together can still
  hold every slot until their idle timeout. Close the oldest idle connection when full and use a
  shorter first-byte timeout under load (RFC 7766 §6.2.3).
- **[P1] Source address on wildcard UDP listeners.** On a host with several addresses, a socket
  bound to `0.0.0.0` or `[::]` answers from the address the kernel picks, which may not be the one
  the query was sent to. Needs `IP_PKTINFO` / `IPV6_RECVPKTINFO`; until then, list specific
  addresses on multihomed hosts.
- **[P2] Rate limiting exemptions for trusted networks** (beyond loopback), and rate limiting
  statistics in metrics.
- **[P3] Binding the floating IP before it is assigned** (`IP_FREEBIND`), for VRRP backups.

## Phase 2: v0.2 control

- **[P2] Prometheus metrics** endpoint.
- **[P2] API compatibility checks.** Use oasdiff on the OpenAPI spec for `/api/v1`, and evaluate
  `cargo-semver-checks` if any crate is published.
- **[P2] JSON log format option** (for example `--log-format json`) for log shippers.

## Phase 4: v0.4

- **[P4] EDNS padding (RFC 7830 / RFC 8467)** for DoT, DoH and DoQ, both server and upstream.
- **[P4] Differential fuzzing** of `HickoryCodec` against the fast-path decoder, once it exists.

## Phase 5: 1.0

- **[P5] Private fuzzing before the first release.** The weekly fuzz job runs in the public
  repository, so its findings are public. Move it to a private mirror or OSS-Fuzz (with private
  bug reports) before goethite has users.
- **[P5] SBOM and signed, reproducible releases.**
- **[P5] Landlock and seccomp sandboxing.**

## Unscheduled / tooling

- **[later] Persist the fuzz corpus in CI** (cache or artifact) so weekly runs build on previous
  coverage instead of starting from the seeds.
- **[later] CI canary job** on `beta` or the latest stable toolchain, to catch upcoming lint and
  compiler changes before an MSRV bump.
- **[later] Site polish:** OG images, search tuning, a logo, and a richer landing page.
- **[later] Pin the fuzzing nightly** to a dated toolchain so weekly fuzz runs are reproducible.
- **[later] Lint workflows in CI** with actionlint and zizmor.
- **[later] `multiple-versions = "deny"` in `deny.toml`** once the remaining duplicate
  (`syn`, through build-time dependencies) is gone.
