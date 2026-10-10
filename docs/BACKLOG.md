# Backlog

Work noticed along the way and not scheduled yet. Per [`AGENTS.md`](../AGENTS.md), we note these
items here instead of building them inside an unrelated change. Phases 0 to 5 have shipped, Phase N
as v0.N (see the [changelog](../CHANGELOG.md)); each item keeps the tag of the phase it was first
meant for, and `[later]` marks the ones that never had one. Findings of the code review carry their
severity instead: `[high]`, `[medium]` or `[low]`. When an item is picked up, move it into an issue
or PR and delete it from this list.

## Code review (2026-10-10)

A read-through of `development` at `b7b65f1` (v0.5.0 plus OpenTelemetry) for bugs, security,
performance and weight; `cargo xtask ci` passed. Every item comes from reading the code, not from a
running system, so start each fix with a test that shows the failure. Within each area the most
severe come first.

### Filtering and resolution

- **[medium] The NSEC3 hash budget is per set, not per query.** `MAX_HASHES` (64) applies to each
  `Nsec3Set`, and `ds_denial` and `nsec3_nodata` build new ones at every step of the trust walk, so
  unsigned names deep under a zone with 150 iterations cost thousands of hashes per query
  (CVE-2023-50868 class). Keep one budget in `Validation`; running out is SERVFAIL, not bogus.
- **[medium] Bogus after one server.** Validation uses whichever server answered first, and a
  broken chain is cached as bogus for the zone for 60 s: one stale secondary serving expired
  signatures fails the whole zone. Try other servers before declaring it bogus.
- **[medium] One spoofed case mismatch turns 0x20 off for good.** `exchange.rs` ends an exchange
  on the first reply that matches except for case, and `infra.rs` then turns 0x20 off for that
  server's address permanently, so an off-path spoofer can remove it before spoofing again. Keep
  waiting on a mismatch, and turn 0x20 off only after repeated mismatches without an exact match,
  for a limited time.
- **[medium] A SERVFAIL for one name marks the upstream down.** `forward_from` in `forward.rs`
  counts a SERVFAIL as an upstream failure and moves on to the next upstream, and SERVFAIL is never
  cached (RFC 9520). With Quad9 first and the router second, `dnssec-failed.org` gets the router's
  unvalidated answer cached, and three such lookups mark Quad9 down for 30 s. Count only transport
  errors and timeouts, do not fail over on SERVFAIL from a validating upstream, and cache SERVFAIL
  for a few seconds.
- **[medium] Rebinding protection misses SVCB and HTTPS hints.** `rebinding.rs` strips A and AAAA
  records only; `ipv4hint` and `ipv6hint` pass, and clients may connect to hints before A and AAAA
  arrive (RFC 9460 7.3). The local-use NAT64 prefix `64:ff9b:1::/48` (RFC 8215) is not treated as
  private either.
- **[medium] Forwarding sends local names to the upstream.** `Recursor::special` runs only when
  recursing, so `home.arpa`, `local`, `invalid` and the private reverse zones of RFC 6303 go to the
  public upstream when forwarding. Apply the table in both modes, with an opt-out for an upstream
  that is the router.
- **[medium] The DoT upstream pool has no cap.** `tls.rs` keeps 4 idle connections and no limit on
  open ones: every miss beyond 4 in flight opens and closes its own TLS connection, and past about
  470 new connections a second `connect` fails with `EADDRNOTAVAIL` (TIME_WAIT). Identical misses
  are not merged. Put the pool behind a semaphore that queues queries, and coalesce identical
  misses. When a DoH upstream connection closes, every query in flight reconnects on its own; share
  one reconnect.
- **[low] Upstream TC is cleared.** `to_client` in `forward.rs` resets TC, so a truncated answer
  relayed by a DoH or DoT upstream is cached and served as complete. Copy TC and do not cache it.
- **[low] goethite's own lookups skip local records.** `lookup_addresses` (list downloads, the
  collector) checks the built-in records only, not the policy's local records, and applies
  rebinding protection, so a collector at `otel.lan` or at a private address cannot be found by
  name.
- **[low] An upstream can be goethite itself.** `config.rs` accepts `address = "127.0.0.1"` while
  goethite listens there; each miss forwards to itself until the in-flight cap is full. Refuse
  upstreams that match a listen address.
- **[low] Each failed query logs a warning.** `forward.rs` logs every failed query, with its name,
  at the default level: 300 queries a second for a name that times out reach journald's rate limit,
  which then drops all of goethite's logs, and they go to the collector too. Sample it as
  `guard::worth_logging` does (see the per-packet debug log item under Phase 1).
- **[low] Lameness is per address, not per zone.** `infra.rs` marks a server address lame or down
  for every zone, so a zone delegated to a TLD's or a DNS provider's addresses can steer queries
  away from them for 60 s.
- **[low] Synthesized CNAMEs keep the server's TTL.** `validate.rs` caps a DNAME to its signature,
  but not the CNAME synthesized from it.
- **[low] Signed DNAMEs with an uppercase target fail.** hickory reads DNAME as unknown RDATA and
  puts it in canonical form unchanged; RFC 4034 6.2 lowercases the target. Lowercase type 39 RDATA
  in `verify` in `crates/goethite-proto/src/dnssec.rs`.
- **[low] ECS opt-out gets FORMERR.** `hickory_codec.rs` rejects client subnet family 0, which
  `dig +subnet=0` sends; accept it with prefix 0 and no address.
- **[low] NSEC, NSEC3 and DNAME print as `TYPE47`, `TYPE50` and `TYPE39`** in the query log and
  the API: `mnemonic` in `types.rs` lacks them (and NSEC3PARAM, TLSA, CAA, NAPTR).

### DNS listeners

- **[medium] One client can take every UDP slot.** `serve_udp` takes one of 2,048 in-flight slots
  before decoding and the cache, with no cap per client (TCP has one). Queries for a slow zone hold
  a slot for 4 to 6 s, so a client within its rate limit, or an exempt network, fills them, and
  every other client's queries are dropped, cache hits too. Cap in-flight queries per client
  network, or answer cache hits before taking a slot.
- **[medium] The rate limiter fails real clients under a spoofed flood.** In `limits.rs`, a full
  shard sweeps once a second and drops every refilled bucket, including those of clients idle for
  a few milliseconds; networks it cannot track share one overflow bucket that the flood keeps
  empty, and their TCP retries get REFUSED by the same limiter. A fixed array of GCRA cells indexed
  by a keyed hash needs no sweep and no overflow bucket.
- **[low] Shutdown and upgrade drop pipelined TCP queries.** The biased stop branch in
  `serve_messages` (`stream.rs`) wins even when a query is already buffered, and closing with unread
  data sends a reset, although ADR 0012 promises no drops. Answer buffered queries, then half-close.
- **[low] DoQ keeps the address from the handshake.** quinn allows migration by default, but
  `quic.rs` uses the accept-time address for access lists, policy and the rate limit on every
  stream. Read `remote_address` per stream, or turn migration off.
- **[low] Accept errors log at debug level only.** When file descriptors run out, `stream.rs`
  retries every 100 ms with no warning or metric. Add a rate-limited warning and a counter.

### Control plane, API and store

- **[medium] The documented dual-stack API address stops startup on Linux.** The API, cluster and
  witness listeners bind without `IPV6_V6ONLY` (`bind_tcp` in `sockets.rs`, `ApiListeners::bind`),
  so `listen = ["0.0.0.0:8053", "[::]:8053"]` from the API docs fails with "address in use" and the
  node does not start. With `[::]` alone, IPv4 peers arrive as `::ffff:a.b.c.d`, which `/api/docs`
  refuses as not loopback and the web UI's leak test does not match. Set `only_v6(true)` as
  `goethite-server/src/bind.rs` does.
- **[medium] No-token mode trusts a reverse proxy on the same host.** Without a token, a proxy on
  the host forwards every client as loopback with an accepted `Host`, so scripts through it get
  admin access (browsers are still stopped by the `Origin` check). Without a token, refuse requests
  that carry `Forwarded`, `X-Forwarded-For`, `X-Real-IP` or `Via`, and say in the docs that a proxy
  needs a token.
- **[medium] Failed list downloads wait a whole interval.** The refresh loop in `control.rs` sleeps
  `list_update_hours` whatever happened, so a node that boots before its network is up has no lists
  for a day. Retry failed and never-downloaded lists with backoff.
- **[medium] An API timeout throws away a committed rebuild.** Handlers await `rebuild_filter`
  inside the 30 s `limit_time`; on a timeout the compiled filter is dropped although the change is
  in the store, and the client gets 500 for a saved change (a retried `POST /rules` duplicates it).
  Rebuild in a detached worker that coalesces requests; handlers wait with a timeout but never
  cancel.
- **[medium] Migrating recompiles once per item.** `goethite migrate --apply` posts lists and rules
  one by one, and each triggers a full recompile of every list. With the client's 10 s timeout,
  committed items are reported as failed, and a re-run skips groups that exist by name without
  fixing their lists, against ADR 0030's "repeatable". Coalesce rebuilds (the item above), refresh
  the lists once at the end, and reconcile existing groups.
- **[medium] The OpenTelemetry latency histogram takes a lock per query.** `BoundHistogram::record`
  locks a `std::sync::Mutex` in `opentelemetry_sdk` 0.33: one lock shared by all DNS workers, two
  with an OTLP reader. ADR 0040 says one atomic update and no lock, and
  `benches/query-metrics.rs` runs on one thread with one reader. Keep latency buckets in relaxed
  atomics behind an observable instrument, or bench with several threads and both readers first.
- **[medium] The audit log is capped by count, not size.** Every entry stores the whole before and
  after JSON; a large settings resource is about 1 MB per change, so 100,000 kept entries can reach
  tens of GB and one page of 100 hundreds of MB. Store diffs for large resources, keep a byte
  budget, and limit pages by bytes.
- **[medium] Query log pruning blocks the store's writer.** `querylog.rs` enforces its size cap once
  a minute by removing rows one at a time in a single transaction, on the redb writer that config
  changes and the Raft log also use, and every batch commit is durable. At 10,000 queries a second
  that is about 600,000 rows, while the 16,384-entry queue drops log entries. Delete by range,
  enforce the cap per batch, and use non-durable commits or a separate file for the log and
  statistics (see the query log writer item under Phase 2).
- **[low] Peak memory while refreshing lists.** A list is held 3 to 4 times: `download.rs` copies
  the body twice (`to_bytes`, then `to_vec`), `validate` in `lists.rs` builds a whole
  `FilterBuilder` only to count rules, and `read_list` copies valid UTF-8 through
  `from_utf8_lossy().into_owned()`. The builder allocates per rule (`Vec<(Vec<u8>, Source, u8)>`),
  about 80 MB per million rules next to the live filter. Use `Vec::from(Bytes)`,
  `String::from_utf8` with a lossy fallback, a parse that only counts, and one buffer for all keys.
  This matters on 1 GB boards.
- **[low] The Bloom filter is sized for keys, not anchors.** `count_keys` sizes it for distinct
  keys, but only top-two-label anchors go in, and the size is rounded up to a power of two: 2 MiB
  where about 125 KiB gives the same false-positive rate in `benches/filter.rs`. ADR 0004 and
  `bench/README.md` give the size without the rounding.
- **[low] The compiled filter is swapped before the policy is built.** `rebuild_filter` in
  `control.rs` replaces `compiled` before `rebuild_policy` succeeds; on a `PolicyError` queries keep
  the old filter while `/status` shows the new one, and the next group edit activates it. Build
  both, then swap.
- **[low] The store's schema version is overwritten on open.** `store.rs` writes `"2"` without
  reading the old value, so a downgrade relabels a newer store. Read it first and refuse a newer
  one.
- **[low] Each change re-validates the whole configuration** under the writer lock, and again on
  each member: up to 50,000 rule parses for one change. Validate the changed resource and its
  references.
- **[low] Statistics block a tokio worker.** `stats_top` runs on the async thread while holding the
  aggregator mutex the query log writer needs. Use `spawn_blocking`, and keep finished hours in an
  `Arc`.
- **[low] The API rebuilds things per request.** The router is re-layered for every connection,
  `goethite-api/src/cluster.rs` builds a router for every forwarded change, and the OpenAPI
  document is generated on every request. Build each once.
- **[low] Any token whose SHA-256 matches is accepted.** `auth.rs` never checks the `gth_` plus 64
  hex digits format, so an operator can put an unsalted hash of a password in the config. Refuse
  other formats.
- **[low] Migration output and secrets.** The migrate report prints the old server's text (list
  addresses, regexes, client names) as is, so a hostile server can send terminal escape sequences;
  `text_name` keeps control characters the store refuses, so such groups fail to import. Escape them
  in the report and strip them from names. `Options` in `goethite-tui` (the token) and `Source` in
  `goethite-migrate` (the password) derive `Debug` without redaction; migrate sends credentials to
  `http://` sources without the warning the API and OTLP paths give; and `user:pass@` in `--from`
  or `--api` ends up in error messages.
- **[low] A partial AdGuard `allowed_clients` is imported.** Entries goethite cannot parse are
  skipped, so those clients get REFUSED, and if all are skipped everyone is allowed. Skip the whole
  list, with a note.
- **[low] List files and validators.** `lists.rs` sends `ETag` and `Last-Modified` even when the
  list file is gone (a 304 then leaves it never downloaded); a failed `.meta` write after the list
  was replaced reports the download as failed, with no rebuild; files of removed lists are never
  deleted; and the redirect loop follows 4 redirects instead of 3.
- **[low] A second SIGTERM is ignored** (`main.rs`), so a stalled shutdown needs SIGKILL.

### Cluster and sandbox

- **[medium] Raft messages are not tied to the sender's certificate.** `raft/routes.rs` never
  compares the TLS identity with the member a vote or AppendEntries names, and openraft accepts any
  equal or higher vote. A witness or learner with a valid certificate can append changes as a
  made-up leader, or vote in another member's name: more than the accepted risk in the threat
  model. Require the Raft ID in the certificate to match the leader (append, snapshot) or the
  candidate (vote).
- **[medium] Large configurations never replicate.** openraft gives AppendEntries the 500 ms
  heartbeat and each snapshot chunk `install_snapshot_timeout`, which goethite leaves at 200 ms,
  with a new TLS connection per message and no backoff. A configuration near `MAX_RULES` (about
  10 MB) never reaches a new or lagging member, and the retries encode JSON on the DNS workers. Set
  the timeout, take a snapshot right after the Seed, lower `max_payload_entries`, and move Raft
  JSON into `spawn_blocking` (see configurable Raft timeouts under Phase 5).
- **[medium] seccomp can be bypassed with x32 system calls.** seccompiler checks the architecture
  only, which x32 calls share with x86-64, and the deny-list's default is to allow: a call number
  with `0x40000000` set passes every rule. The units set `SystemCallArchitectures=native`;
  containers and other init systems do not. After the architecture check, return `EPERM` for
  numbers at or above `0x40000000`.
- **[medium] In-place upgrades stack sandboxes.** The new goethite starts as a child of the old one
  and adds a Landlock layer to the one it inherits; the kernel allows 16, so about the 16th upgrade
  without a restart fails in `restrict_self`. `postinstall.sh` sends `SIGUSR2` with `|| true` and
  returns, so the package reports success while the old binary keeps answering. Treat a full stack
  as already sandboxed, or re-execute through systemd; and have the script wait for `MainPID` to
  change, with a loud warning if it does not.
- **[medium] A bootstrap node with an empty store can start a second cluster.** The only guard is
  that no member answered in one round of checks at startup: after a power cut that lost its store,
  the bootstrap node starts a new cluster while the others continue the old one. Bootstrap only
  after a member answers that it is in no cluster, or after several rounds.
- **[low] A failed cluster start leaves no Seed.** `raft/node.rs` saves the cluster ID before the
  leader wait and the Seed write; if either fails nothing retries, and members added later drift
  apart. Retry the Seed, or remove the ID.
- **[low] Landlock scopes are not used.** The crate supports `Scope::Signal` and
  `Scope::AbstractUnixSocket` on the ABI goethite asks for; add them, after checking
  `NOTIFY_SOCKET` and the upgrade's signals.

### Packaging, CI and the web UI

- **[medium] Installs answer everyone.** `deploy/goethite.toml` listens on every address and an
  empty access list admits every client; the TOML cannot set access, and the Compose file
  publishes port 53 on every address, past ufw and firewalld. An install on a VPS is an open
  resolver. Default the allowed list to loopback, private, ULA, link-local and CGNAT addresses
  until an admin changes it, or accept a first allowed list in the TOML.
- **[medium] The image check accepts any branch.** The documented `gh attestation verify` for the
  image (`site/src/content/docs/verify.md`) pins the workflow but not `--source-ref`, the push job
  in `image.yaml` has no protected environment, and `workflow_dispatch` runs the workflow from any
  branch. Add `--source-ref refs/tags/vX.Y.Z`, and limit the job to tags.
- **[medium] `image.yaml` checks out the tag by its short name.** `ref: ${{ env.TAG }}` would take
  a branch named like the tag. Use `refs/tags/...`, check the tag against a version pattern, and
  move `latest` only for the newest release.
- **[low] The image misses base image fixes between releases.** It is built on release only; a
  scheduled rebuild on a new base digest, or a patch release policy for base image CVEs, would pick
  up glibc fixes.
- **[low] Renovate's cooldown and lock file maintenance.** Check whether `minimumReleaseAge`
  applies to `lockFileMaintenance`; if not, the weekly rewrite can take transitive versions
  published minutes earlier.
- **[low] `web/` has no `.npmrc`.** `site/` sets `ignore-scripts=true`; a local `npm ci` in `web/`
  still runs install scripts.
- **[low] CI and the units.** `systemd-analyze verify` in CI skips `goethite-vrrp.service`, the
  most privileged unit; only the chaos workflow sets `timeout-minutes`; and no unit has
  `WatchdogSec=` with a ping that proves the DNS path is alive, so a hung single node stays down.
- **[low] The web UI is served uncompressed.** Its 200 KiB budget is measured gzipped, but
  `goethite-api/src/web.rs` serves raw files with no `Content-Encoding`, about 3 times the bytes.
  Compress at build time, as `docs.mjs` does for Scalar.
- **[low] The TUI ships in every server build.** It brings about 30 of the binary's crates
  (crossterm, ratatui, a second hashbrown, derive_more 2, darling, strum); a default-on `tui`
  feature that the package and image builds turn off would drop them. The other duplicate crates
  (rand 0.8 and 0.9, thiserror 1, derive_more 1) come from openraft 0.9 and the OpenTelemetry SDK.

### Hot path

- **[low] Per-query costs the benches cannot see.** Every UDP query spawns a task and makes two
  allocations (`wire.to_vec()`, the output buffer), cache hits included; each query makes about
  five contended atomic updates (`load_full` of the policy, a clone of the default group's
  `Arc<str>`, global hit counters); names are hashed byte by byte, twice per lookup; padded
  responses are encoded twice; and TCP, DoT and DoQ answers are copied into a separate frame. The
  benches run on one thread. Add a multi-threaded criterion bench first, then pool buffers, use
  `load`, carry a group index, count per shard, and hash names once from a lowercased stack buffer.
- **[low] Cache compaction stalls a shard.** `compact` in `cache.rs` runs a `retain` with a hash
  lookup over the whole order queue while holding the shard's mutex: about 10 ms at 1,000,000
  entries, during which every worker that needs the shard waits. Compact a little at a time (see
  smarter eviction under Phase 1).

## Phase 1: v0.1 core blocker

Phase 1's scope shipped in v0.1.0. These items came up along the way; they are candidates for
0.1.x releases or for Phase 2.

- **[P1] Raise the open file limit at startup.** Every UDP query in flight forwards over its own
  socket, so the default soft limit of 1024 can run out under load. The systemd unit sets
  `LimitNOFILE=65536`; goethite could raise its soft limit to the hard limit itself.
- **[P2] Users from the name service switch.** `server.user` is looked up in `/etc/passwd`
  only; accept a numeric `uid:gid` for users that live in LDAP or systemd-homed.
- **[P1] Config file hot reload** via `arc-swap`, without dropping queries, on `SIGHUP` as well
  as the filter lists and certificates it reloads today: upstreams, recursion and cache settings
  are read once at startup. Settings in the store already apply live, and `SIGUSR2` re-reads the
  file only by handing over to a new process.
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
- **[later] Serve-stale and prefetch** (RFC 8767): answer from an expired entry while refreshing it
  in the background, and refresh popular entries shortly before they expire.
- **[later] Smarter eviction.** The cache evicts the oldest entry first. Compare S3-FIFO or LRU
  with the benches and a realistic query mix before changing it.
- **[P1] OPT in FORMERR/NOTIMP responses.** Header-only error responses omit the OPT record even
  when the query carried one (RFC 6891 §7). Only BADVERS includes it today.
- **[P1] SOA in negative answers.** NODATA for local names carries no SOA in the authority
  section, so clients cannot cache it negatively (RFC 2308). Now that local records are
  configurable (ADR 0029), NODATA for them lacks it too.
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
- **[later] Signed or hash-pinned lists**, for list sources that publish signatures.
- **[P1] Name parsing for filter lists.** `Name::from_str` only accepts host-style names (no
  escapes, no wildcards). Filter syntax needs wildcards and may need RFC 1035 escapes; extend the
  parser (and its `parse-name` fuzz target) rather than adding a second one.
- **[P1] TCP fairness under load.** Per-client limits exist, but many hosts together can still
  hold every slot until their idle timeout. Close the oldest idle connection when full and use a
  shorter first-byte timeout under load (RFC 7766 §6.2.3).
- **[P1] Source address on wildcard UDP listeners.** On a host with several addresses, a socket
  bound to `0.0.0.0` or `[::]` answers from the address the kernel picks, which may not be the one
  the query was sent to. Needs `IP_PKTINFO` / `IPV6_RECVPKTINFO`; until then, list specific
  addresses on multihomed hosts.

## Phase 2: v0.2 control

Phase 2's scope shipped in v0.2.0. The `[P2]` items left in this file are candidates for 0.2.x
releases.

- **[P2] Scoped API tokens:** read-only tokens (for monitoring), beside the single admin token.
- **[P3] Query log writer priority and cost.** The writer thread competes with the DNS workers
  for CPU when the node is saturated. Lower its priority (it needs `setpriority`, which the
  systemd unit's `~@resources` filter refuses), and cut its per-entry allocations (names, IDs and
  rule text are turned into `String`s for every stored entry), with a criterion bench.
- **[P5] `cargo-semver-checks`** if any crate is published (the HTTP API is already checked
  with oasdiff).
- **[P2] JSON log format option** (for example `--log-format json`) for log shippers.

## Phase 3: v0.3 HA

Phase 3's scope shipped in v0.3.0. These items came up along the way.

- **[P4] An IPv6 floating IP:** VRRPv3 over IPv6 (link-local sources, `ff02::12`), with
  unsolicited neighbor advertisements instead of gratuitous ARP, and `IPV6_FREEBIND`.
- **[P4] Several floating IPs per pair,** for example one per VLAN, or a second address so each
  node normally holds one and clients spread over both.
- **[P4] The floating IP in the API, TUI and web UI.** `goethite vrrp` is a separate process; the
  node could report whether it holds the address (it can see that from its interfaces) and the
  helper's state, for example through a status file in the runtime directory.
- **[P4] Link state in VRRP.** A node whose interface goes down keeps the address until the link
  returns and it hears the peer; watching link events over netlink would release it at once.

## Phase 4: v0.4

- **[P4] Forward chosen domains while recursing:** `printer.lan` or `fritz.box` to the router,
  everything else from the root down, like AdGuard Home's per-domain upstreams.
- **[later] Recursion extras:** coalescing identical queries in flight, prefetching popular
  names before they expire, serving stale answers when servers are unreachable (RFC 8767),
  NXDOMAIN cuts (RFC 8020) and aggressive use of NSEC and NSEC3 (RFC 8198), now that proofs are
  validated.
- **[later] Leak tests for the whole cluster:** a test only sees lookups that reach the node that
  made it; nodes could share test names over the cluster channel, so a pair counts lookups at
  either node.
- **[later] An open leak test page** for devices whose users have no admin token (family
  devices): a page that runs one test and shows only its own result, with its own rate limit.
- **[later] Stopping bypasses, not just seeing them:** answering the canary domain
  `use-application-dns.net` with NXDOMAIN (Firefox then keeps its DoH off), and a guide for
  redirecting port 53 at the router. Known DoH resolvers are already blocked by the HaGeZi bypass
  list in the Strict and Family presets.
- **[later] Extended DNS Errors (RFC 8914):** say why an answer is SERVFAIL (DNSSEC bogus,
  signature expired, no reachable authority) or blocked (filtered), for clients and the query
  log.
- **[later] More DNSSEC controls:** negative trust anchors (RFC 7646) for domains whose DNSSEC
  is broken, configurable trust anchors and RFC 5011 tracking of root key rollovers (the anchors
  are built in today), and the bogus count per domain in the query log.
- **[later] Validating forwarded answers:** forwarding neither validates nor passes on an
  upstream's AD flag; validating with the upstream's DS and DNSKEY answers would let forwarding
  nodes set AD too.
- **[later] Oblivious DoH upstreams:** goethite's own queries to an upstream through an ODoH
  proxy, so the upstream does not learn the network's address. And being a proxy itself.
- **[later] ODoH configurations in DNS:** an `HTTPS` record carrying the target's key, so
  clients need not fetch `/.well-known/odohconfigs`.
- **[P4] DoQ address validation tokens.** Every new DoQ connection costs a Retry round trip;
  NEW_TOKEN tokens would let returning clients skip it, but quinn keeps their replay protection
  in its `bloom` feature (another dependency).
- **[later] DoH over HTTP/3,** on the QUIC stack DoQ already uses.
- **[P4] DoH behind a reverse proxy:** plain HTTP from configured trusted proxies, with the
  client address from `X-Forwarded-For` or `Forwarded`, for setups where a web server owns port
  443.
- **[P4] Check the certificate against `server_name`.** goethite does not check that the DNS
  certificate covers `server_name` and `*.<server_name>`, or warn before it expires; both need an
  X.509 parser (a new dependency).
- **[P4] systemd credentials for TLS keys.** `LoadCredential=` would let the unit read
  root-only keys without a group, but systemd in the test container does not mount credentials
  even for a bare unit, so it is untested and undocumented. Try it on a real host; it needs a
  restart, not a reload, after renewal.
- **[P4] Reload without `/bin/kill`.** `ExecReload=` runs `/bin/kill`, which minimal systems
  (and the systemd test image) lack. `Type=notify-reload` (systemd 253) with `ReloadSignal=SIGHUP`
  needs goethite to report `RELOADING=1` and `READY=1` around a reload.
- **[later] Presets in the API and TUI:** presets are applied by the web UI, one change at a
  time; an API call would apply one in a single store transaction, for the TUI and scripts.
- **[later] `$dnsrewrite=NXDOMAIN` rules,** which only block: the services catalog's iCloud
  Private Relay uses nothing else, so goethite leaves that service out today.
- **[P5] Local records in the TUI:** a read-only Records tab (ADR 0029).
- **[later] More local record types** (TXT, MX, SRV), automatic PTR answers for local `A` and
  `AAAA` records, and local records per group.
- **[later] Per-client rate limits for Oblivious DoH:** the rate limiter skips it because its peer
  is the proxy, so only the connection limits bound it. Nothing checks that the peer is a proxy,
  though: any client can fetch `/.well-known/odohconfigs` and query directly. Give ODoH its own,
  higher limit, or accept it only from known proxies.
- **[P4] Differential fuzzing** of `HickoryCodec` against the fast-path decoder, once it exists.

- **[P4] Scalar's AI SDK advisory.** `npm audit` reports a low-severity resource consumption
  issue (GHSA-866g-f22w-33x8) in `@ai-sdk/provider-utils`, which `@scalar/api-reference` pulls in
  for its chat agent; goethite turns the agent off. Update Scalar once it ships a fixed version.
- **[P5] The web UI's JS budget is full:** 199.8 of 200 KiB gzipped (every chunk counts, lazy ones
  too) after the cluster page. The next page needs a deliberate raise or a trim first.
- **[later] Ask TanStack Charts for a CSP-friendly root.** Its SVG root carries an inline style,
  which goethite strips (ADR 0017); an option to leave it out would remove the workaround.

- **[P4] dnsperf for v0.4.0 on a quiet machine.** The release run (bench/README.md) was on a busy
  host: no regression against v0.3.0, but the sub-millisecond p99 was not shown for v0.4.0.

## Phase 5: v0.5

- **[P5] The external security review** of v0.5.0 is still ahead: the brief is
  [`security-review.md`](security-review.md), and its findings become issues.
- **[later] Landlock network rules for outgoing connections.** The sandbox stops new TCP
  listeners only: upstreams, list hosts and cluster members can be on any port, some of them
  added at run time. Restricting outgoing TCP to the ports in use would need the policy to follow
  the configuration (ADR 0032).
- **[later] Namespaces through `clone` and `clone3`.** The filter refuses `unshare` and `setns`,
  but checks neither `clone`'s flags nor `clone3` (whose flags seccomp cannot see), so either can
  create namespaces where systemd's `RestrictNamespaces=` does not apply. Refuse `clone` with any
  `CLONE_NEW*` flag, and return `ENOSYS` for `clone3` so the C library falls back to `clone`.
- **[later] The sandbox in the status API and the metrics**, not only the log.
- **[later] Leadership transfer.** openraft 0.9 cannot hand leadership to another member, so
  `promote` inside a healthy cluster is refused rather than moving the leader (for example
  before maintenance). openraft 0.10 can; revisit when it is stable (ADR 0031).
- **[later] The cluster page in the TUI:** the web UI's Cluster page (health, voters it can
  lose, a card per member, recovery steps) as a TUI view; the TUI's header shows the cluster only.
- **[later] Each node's counts on the cluster page.** `GET /api/v1/stats?scope=cluster` returns the
  sum and the names of the nodes in it; a per-node breakdown would show which member answers how
  much.
- **[later] Cluster metrics:** this node's Raft state, term, leader changes and how far each
  member's log reaches, in Prometheus metrics.
- **[later] Keep-alive connections between members.** Raft opens a TLS connection per message
  (session resumption keeps it cheap), about two a second per follower.
- **[later] Configurable Raft timeouts** for members across a WAN; they are constants tuned for
  a LAN today.
- **[later] Learners that never vote,** for read-only members in another site, kept as learners
  even when they would make three voters.

## 1.0 competitor parity (2026-10-10)

Gaps the competitor review (AdGuard Home v0.107.79, Pi-hole v6.4.3, Numa v0.24.1) found and that
no section above covers; the review's other gaps are already items here. Its filtering gaps are
what "match AdGuard Home on everyday filtering" ([`AGENTS.md`](../AGENTS.md)) still asks for.

- **[later] A custom IP as the blocked answer,** beside the null IP, NXDOMAIN and REFUSED modes.
- **[later] Answer filtering by IP:** `|10.*`-style and hosts-style rules matching A and AAAA
  answers, in the response pass CNAME uncloaking already runs.
- **[later] A rule tester:** which rule blocks a name, for which client, as an API endpoint and a
  page (AdGuard Home's `check_host`; the TUI could use it too).
- **[later] `$ctag`, and the rest of `$dnsrewrite`** beyond the `$dnsrewrite=NXDOMAIN` rules noted
  in Phase 4: answer records and the other RCODEs.
- **[later] Per-domain upstreams while forwarding,** the counterpart of the recursing item in
  Phase 4.
- **[later] Hedged upstream requests:** send a second query after a short delay instead of waiting
  for the first to time out (as Numa does).
- **[later] Upstreams per client or group** (AdGuard Home).
- **[later] AAAA filtering and DNS64** (AdGuard Home; Numa filters AAAA only).
- **[later] EDNS Client Subnet as the client's identity** for a node behind another forwarder
  (Pi-hole).
- **[later] DoQ and HTTP/3 upstreams,** the client side of the transports goethite already serves.
- **[later] PROXY protocol v2 on listeners** (Numa; requested of AdGuard Home with 95 votes).
- **[later] Backup and restore of the whole configuration,** as Pi-hole's Teleporter does; today
  `goethite migrate` is import-only.
- **[later] Apple configuration profiles** for the DoT and DoH setup (`.mobileconfig`).
- **[later] Client names from reverse DNS, ARP or the OS hosts file,** like AdGuard Home's
  friendly names.
- **[later] Leaving chosen names or clients out of the query log** (AdGuard Home's ignored-host
  list and per-client flag).
- **[later] Flushing the cache from the API,** and from the web UI.
- **[later] DHCP: a scope decision for 1.0** (AdGuard Home and Pi-hole both ship a server;
  goethite does not).
- **[later] Home Assistant: keep the integration outside the project,** as AdGuard Home and
  Pi-hole do; a community integration would use the REST API.

## OpenTelemetry (ADR 0040)

- **[later] Trace context across processes:** W3C `traceparent` on the cluster's connections, so
  a change forwarded to the leader is one trace across both members, and from API clients (the
  TUI, scripts).
- **[later] Tracing one query on demand:** resolve a name through the API and return each step
  (policy, filter decision, cache, upstreams or recursion, DNSSEC), for home-lab users without a
  collector.
- **[later] Telemetry from `goethite witness` and `goethite vrrp`:** they have no resolver to
  find a collector by name and read no files under their sandboxes; they log to standard error
  only.

## Unscheduled / tooling

- **[later] Sign-in events in the audit log.** Sign-ins, sign-outs and failed sign-ins are
  traced, not audited (ADR 0037). `AuditAction` could grow `login`, `logout` and a failure
  action; `store.record` is the tool, but sign-ins are frequent and per-node, so decide whether
  the audit log is the right place first.
- **[later] A self-hosted OIDC provider as a sign-in source.** Authelia, authentik or Keycloak
  on the same network would let a lab keep one directory; goethite becomes a relying party
  (ADR 0037 deferred it). The built-in users stay as the bootstrap fallback.
- **[later] Email delivery for resets and codes.** Needs SMTP configuration and a mail
  dependency (ADR 0037 kept the admin-issued link instead). The `/auth` endpoints would not
  change shape.
- **[later] Session controls.** A list of a user's sessions with per-session revoke, sliding
  expiry on use, and a "sign out everywhere" button: today a user change ends all sessions and
  otherwise they live twelve hours.
- **[later] Regenerating recovery codes** from the account page once some are used up, with the
  password as the confirmation.
- **[later] WebAuthn as a second factor.** Passkeys would beat TOTP for users; a new dependency
  and browser flows.
- **[later] APT and DNF repositories** for `apt upgrade` and `dnf upgrade`: they need a
  long-lived signing key and hosting (ADR 0027).
- **[later] A health check for containers.** The image has no shell or HTTP client, so neither it
  nor the Compose file has a `HEALTHCHECK` (ADR 0036). A `goethite` subcommand that asks the
  running server would give both one; it should ask the DNS listener, not only the API, since the
  data plane must count as up while the control plane is down.
- **[later] `goethite vrrp` as an unprivileged user in containers.** Docker gives a user other
  than root no capabilities, so the cluster's Compose file starts it as root with `CAP_NET_ADMIN`
  and `CAP_NET_RAW`, and it warns that it runs as root (ADR 0036). Switching to a user named in
  the config while keeping `CAP_NET_ADMIN` (`PR_SET_KEEPCAPS`) would end both.
- **[later] Static musl builds** that run on any Linux, including Alpine. musl's allocator is
  much slower under goethite's multi-threaded load, so this needs another allocator (a new
  dependency) and a bench against the glibc build first (see ADR 0026).

- **[later] A chart repository for the Helm chart,** so `helm install` needs no clone, and an
  Artifact Hub listing (ADR 0037). OCI on ghcr.io is the obvious home; it needs release
  automation like the packages' and the image's.
- **[later] The cluster and the witness in the Helm chart.** The chart deploys one node
  (ADR 0037); a Kubernetes cluster wants several members behind one address and no floating IP,
  which is a different shape from Raft plus VRRP and needs its own ADR and HA guide section.

- **[later] Continuous private fuzzing** (a private repository on a schedule, or OSS-Fuzz) once
  goethite has users who would feel a regression between releases (ADR 0028).
- **[later] CI canary job** on `beta` or the latest stable toolchain, to catch upcoming lint and
  compiler changes before an MSRV bump.
- **[later] A Terraform and OpenTofu provider,** generated from the OpenAPI document, for lists,
  rules, local records, groups, clients, schedules and settings. The first one was dropped
  ([ADR 0034](adr/0034-drop-the-terraform-provider.md)); a new one would bring back a `managed_by`
  value that the web UI and the TUI show read-only, and want a token scoped to it.
- **[later] Site polish:** OG images, search tuning, a logo, and a richer landing page.
- **[later] Lint workflows in CI** with actionlint and zizmor.
- **[P5] Complete the web UI's SBOM.** `cargo xtask dist` makes it with `npm sbom --omit=dev`,
  and npm's `.dev` selector also drops every package that a development tool shares with a runtime
  one: on 2026-10-10 the SBOM listed 320 of the 344 runtime packages in `web/package-lock.json`
  (317 of 334 after the move to Vite+, whose Vitest browser packages share three more), while
  `npm run licenses` reads the lockfile and has them all. Without `--omit=dev`, npm marks exactly
  the lockfile's runtime packages `"scope": "required"`; keeping those components (and their
  `dependencies` entries) in xtask's post-processing would match the licence notices. Check the
  result with a full `cargo xtask dist`.
- **[later] `multiple-versions = "deny"` in `deny.toml`** once the remaining duplicate
  (`syn`, through build-time dependencies) is gone.
- **[later] A source link in the web UI and `goethite --version`**, set at build time. The AGPL
  asks a changed goethite to offer its source to the people using it (ADR 0033); a link that a
  fork only has to repoint makes that easy.
