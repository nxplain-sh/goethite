# Backlog

Work noticed along the way and not scheduled yet. Per [`AGENTS.md`](../AGENTS.md), we note these
items here instead of building them inside an unrelated change. Phases 0 to 5 have shipped, Phase N
as v0.N (see the [changelog](../CHANGELOG.md)); each item keeps the tag of the phase it was first
meant for, and `[later]` marks the ones that never had one. When an item is picked up, move it into
an issue or PR and delete it from this list.

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

- **[P2] Scoped API tokens:** read-only tokens (for monitoring) and a Terraform token, beside the
  single admin token.
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
- **[P5] Local records in the Terraform provider and the TUI:** a `goethite_record` resource, and a
  read-only Records tab (ADR 0029).
- **[later] More local record types** (TXT, MX, SRV), automatic PTR answers for local `A` and
  `AAAA` records, and local records per group.
- **[P5] Access lists in the Terraform provider:** `access` (`allowed`, `blocked`) on
  `goethite_settings`, once 0.5.0 is out.
- **[later] Per-client rate limits for Oblivious DoH:** its peer is the proxy, so only the
  connection limits bound it; a proxy could be given its own, higher limit.
- **[P4] Differential fuzzing** of `HickoryCodec` against the fast-path decoder, once it exists.

- **[P4] Scalar's AI SDK advisory.** `npm audit` reports a low-severity resource consumption
  issue (GHSA-866g-f22w-33x8) in `@ai-sdk/provider-utils`, which `@scalar/api-reference` pulls in
  for its chat agent; goethite turns the agent off. Update Scalar once it ships a fixed version.
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
- **[later] Namespaces through `clone3`.** seccomp cannot see `clone3`'s flags, so the filter
  refuses `unshare` and `setns` but not a `clone3` that creates namespaces. Returning `ENOSYS` for
  `clone3` (so the C library falls back to `clone`, whose flags it can check) would close it.
- **[later] The sandbox in the status API and the metrics**, not only the log.
- **[later] Leadership transfer.** openraft 0.9 cannot hand leadership to another member, so
  `promote` inside a healthy cluster is refused rather than moving the leader (for example
  before maintenance). openraft 0.10 can; revisit when it is stable (ADR 0031).
- **[later] Cluster metrics:** this node's Raft state, term, leader changes and how far each
  member's log reaches, in Prometheus metrics.
- **[later] Keep-alive connections between members.** Raft opens a TLS connection per message
  (session resumption keeps it cheap), about two a second per follower.
- **[later] Configurable Raft timeouts** for members across a WAN; they are constants tuned for
  a LAN today.
- **[later] Learners that never vote,** for read-only members in another site, kept as learners
  even when they would make three voters.

## Unscheduled / tooling

- **[later] APT and DNF repositories** for `apt upgrade` and `dnf upgrade`: they need a
  long-lived signing key and hosting (ADR 0027).
- **[later] Static musl builds** that run on any Linux, including Alpine. musl's allocator is
  much slower under goethite's multi-threaded load, so this needs another allocator (a new
  dependency) and a bench against the glibc build first (see ADR 0026).

- **[later] Continuous private fuzzing** (a private repository on a schedule, or OSS-Fuzz) once
  goethite has users who would feel a regression between releases (ADR 0028).
- **[later] CI canary job** on `beta` or the latest stable toolchain, to catch upcoming lint and
  compiler changes before an MSRV bump.
- **[later] Site polish:** OG images, search tuning, a logo, and a richer landing page.
- **[later] Lint workflows in CI** with actionlint and zizmor.
- **[later] `multiple-versions = "deny"` in `deny.toml`** once the remaining duplicate
  (`syn`, through build-time dependencies) is gone.
