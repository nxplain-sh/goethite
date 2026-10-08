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
- **[P2] Rate limiting exemptions for trusted networks** (beyond loopback).

## Phase 2: v0.2 control

Phase 2's scope shipped in v0.2.0. The `[P2]` items left in this file are candidates for 0.2.x
releases.

- **[P2] Scoped API tokens:** read-only tokens (for monitoring) and a Terraform token, beside the
  single admin token.
- **[P5] Release builds include the web UI.** The release workflow must build `web/` before
  `cargo build --release`, reproducibly (pinned Node, `npm ci`).
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

- **[P4] EDNS padding (RFC 7830 / RFC 8467)** for DoT, DoH and DoQ, both server and upstream.
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
  `use-application-dns.net` with NXDOMAIN (Firefox then keeps its DoH off), blocking known DoH
  resolvers' names by a preset, and a guide for redirecting port 53 at the router.
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
- **[P4] Client IDs in the Terraform provider:** `ids` on `goethite_client`, once 0.4.0 is out.
  Its acceptance tests start fresh nodes, which now begin with the Balanced preset's three lists
  in the default group: set `[filter] default_lists = false` in their config when moving them
  to 0.4.
- **[later] Presets in the API and TUI:** presets are applied by the web UI, one change at a
  time; an API call would apply one in a single store transaction, for the TUI and scripts.
- **[P4] Blocked services in the Terraform provider:** `blocked_services` on `goethite_group`,
  once 0.4.0 is out; its test nodes need `[filter] services = false` (or a `services_file`).
- **[later] `$dnsrewrite=NXDOMAIN` rules,** which only block: the services catalog's iCloud
  Private Relay uses nothing else, so goethite leaves that service out today.
- **[P5] Access control beyond client IDs:** allowed and blocked client networks for every
  transport, and per-client query rate limits for DoT and DoH, which are not rate limited today
  (only connection-limited).
- **[P4] Differential fuzzing** of `HickoryCodec` against the fast-path decoder, once it exists.

- **[P4] Scalar's AI SDK advisory.** `npm audit` reports a low-severity resource consumption
  issue (GHSA-866g-f22w-33x8) in `@ai-sdk/provider-utils`, which `@scalar/api-reference` pulls in
  for its chat agent; goethite turns the agent off. Update Scalar once it ships a fixed version.
- **[later] Ask TanStack Charts for a CSP-friendly root.** Its SVG root carries an inline style,
  which goethite strips (ADR 0017); an option to leave it out would remove the workaround.

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
