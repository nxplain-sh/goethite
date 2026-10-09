# goethite threat model

> **Status:** first draft, 2026-10-06, written during Phase 0. This draft is incomplete. Revisit
> it at the start of every phase and whenever a new trust boundary appears (new listener, new
> protocol, new storage, new admin interface).

## 1. System overview

goethite is a DNS filtering resolver that runs on a LAN appliance or server, usually as the DNS
server handed out by DHCP. Each node has a **data plane**: listeners, the resolution pipeline,
cache and upstreams. It also has a **control plane**: REST API, web UI, TUI, cluster sync and
filter list updates. Every node must keep resolving when the control plane fails.

Resolution pipeline: client identification → policy/group lookup → local rewrites → filter check
(including CNAME uncloaking) → cache → upstream (forward or recursive) → DNSSEC validation →
response.

Today (Phase 4 in progress) goethite has UDP and TCP listeners with per-client rate and
connection limits, DNS over TLS, HTTPS and QUIC listeners with client IDs, forwarding over plain DNS,
DoT or DoH with failover, DNS rebinding protection, a cache, filtering per client group from local
and downloaded lists, a query log, a REST API with a web UI and a TUI, a two-node cluster with
replicated configuration and a floating IP, and zero-downtime upgrades.

### Trust boundaries

| #  | Boundary                                      | Direction          | Notes                                                       |
| -- | --------------------------------------------- | ------------------ | ----------------------------------------------------------- |
| B1 | Clients → DNS listeners (UDP/TCP 53, DoT, DoH, DoQ) | untrusted → node | Highest-volume, fully attacker-controlled input; DoT, DoH and DoQ may face the internet |
| B2 | Resolver → upstream resolvers / authoritative servers | node → untrusted | Responses are untrusted; off-path spoofing is possible over plain DNS |
| B3 | Filter list downloads                          | untrusted → node   | Large, third-party-controlled content, parsed on the node    |
| B4 | Admins → REST API / web UI / TUI / Terraform   | semi-trusted → node | Authenticated (Phase 2), can change all behaviour           |
| B5 | Cluster peer ↔ cluster peer                   | peer ↔ peer        | Config replication and VRRP (Phase 3)                       |
| B6 | Local OS: config files, storage, other local users | host ↔ process | goethite runs unprivileged after binding (Phase 1)          |
| B7 | Build and supply chain: crates, npm packages, CI actions, release artifacts | upstream → users | Affects every installation                                  |

## 2. Assets

| Asset                  | Why it matters                                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| **DNS availability**   | If goethite stops answering, the whole network is effectively offline. Crashes and hangs are high severity. |
| **Query privacy**      | DNS queries reveal browsing, devices and habits per client. Query logs and stats concentrate this. |
| **Config integrity**   | Config decides what is blocked, rewritten and forwarded where. Tampering enables redirection and surveillance. |
| **Admin access**       | Whoever controls the API controls every client's DNS.                                            |
| Filter list integrity  | A malicious list can block critical domains (DoS) or be crafted to exhaust parser memory or CPU. |
| Cache integrity        | Poisoned cache entries redirect every client that asks for a name.                              |
| Logs and stats         | Privacy-sensitive. Must also be bounded in size so they cannot fill the disk.                    |

## 3. Attackers

| Attacker                              | Capabilities                                                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **LAN client** (including compromised IoT) | Sends arbitrary packets to the listeners at high rates. Can spoof source addresses on the LAN. Can try filter bypass, cache poisoning via crafted queries, or reflection. |
| **Malicious or compromised upstream** | Returns arbitrary responses: oversized, malformed, wrong answers, long CNAME chains, rebinding answers. |
| **Off-path spoofer**                  | Cannot see traffic but races forged responses to poison the cache (Kaminsky-style).                     |
| **On-path network attacker**          | Can observe and modify plaintext DNS between goethite and upstreams.                                    |
| **Compromised filter list**           | Publishes hostile content: huge files, pathological rules, rules that block essential domains.          |
| **Malicious cluster peer**            | A compromised node, or an attacker on the cluster network, tries to push config or take over the floating IP. |
| **Local unprivileged user**           | Tries to read config, logs or secrets, or to abuse the process's privileges.                            |
| **Supply chain**                      | A compromised crate, npm package, GitHub Action or release artifact.                                    |

## 4. Defenses by phase

Status legend: **done** means implemented as of the end of Phase 0. **planned** means scheduled
for that phase and not implemented yet. Phases follow the roadmap in
[`AGENTS.md`](../AGENTS.md#roadmap-respect-the-order).

| Threat                                      | Controls                                                                                          | Phase | Status  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----- | ------- |
| Crash or panic from malformed packets (B1)  | Bounded parsing in `goethite-proto`. Clippy denies `unwrap`/`expect`/`panic`/indexing/string slicing in non-test code. Malformed packets are dropped and logged at debug. | 0 | done |
| Memory exhaustion from tiny packets (B1)    | Header counts are checked before full parsing (QDCOUNT must be 1, no answer or authority records, at most 2 additional), so a 12-byte message cannot trigger large allocations | 0 | done |
| Log injection via crafted names (B1)        | Names are written in escaped ASCII presentation format (`\DDD`), and parser error text is escaped to printable ASCII, so control characters, newlines and terminal escapes from the wire never reach log lines verbatim | 0 | done |
| Log flooding / amplification (B1)           | hickory-proto's own warnings (which quote packet bytes at several times the packet size) are off by default; goethite logs rejected messages at debug only | 0 | done |
| Memory-safety bugs                          | `unsafe_code` denied workspace-wide, and `#![forbid(unsafe_code)]` in every crate root except the binary and goethite-cluster, whose one `unsafe` item each is listed below ([ADR 0025](adr/0025-standard-rust-project-layout.md)) | 0     | done    |
| Parser bugs found too late                  | cargo-fuzz targets `decode-query` (round-trip property) and `parse-name` (display/parse property), weekly CI fuzz run, proptest round-trip and garbage-input tests | 0 | done |
| Malformed or abusive EDNS data (B1)         | EDNS options are checked before parsing: options running past the OPT record, COOKIE options of the wrong length and inconsistent client-subnet options get FORMERR. Zone transfers are refused and meta query types get FORMERR | 0 | done |
| Reflection / response loops (B1)            | Messages with QR=1 (responses) are dropped, never answered                                         | 0     | done    |
| Oversized UDP responses / amplification     | UDP responses fit the client's limit (512 without EDNS, at most the advertised EDNS size). goethite advertises 1232 and sets TC when truncating. | 0 | done |
| TCP resource exhaustion (B1)                | TCP connection cap, idle timeout, 2-byte length framing (RFC 7766)                                 | 0     | done    |
| One client holding every TCP slot (B1)      | At most 16 connections per client (an IPv4 address or an IPv6 /64) by default, out of 256; idle connections close after 10 s. Many hosts together can still fill the slots: closing the oldest idle connection when full and a shorter first-byte timeout under load (RFC 7766 §6.2.3) are in the backlog | 1 | partial |
| Accidental exposure of a dev build          | Development default listens on `127.0.0.1:15353`                                                   | 0     | done    |
| Config typos silently changing behaviour    | Unknown TOML fields are rejected. The config file size is bounded.                                 | 0     | done    |
| Supply chain (B7)                           | `cargo deny` (licenses, advisories, bans, sources) and `cargo audit` in CI for the main and the fuzz workspace. GitHub Actions pinned to commit SHAs. Minimal workflow permissions. | 0 | done |
| Crash details disclosed by public CI fuzzing | Crash artifacts are kept 7 days; the trade-off is documented in SECURITY.md. Fuzzing moves to a private setup before the first release | 0 / 5 | partial |
| Unknown threats                             | This threat model                                                                                  | 0     | done    |
| Off-path spoofed upstream answers (B2)      | A fresh UDP socket per exchange with an OS-randomized source port, connected to the upstream; random 16-bit IDs; 0x20 case randomization; a response is accepted only if its ID, opcode and question in exactly the sent case match. Mismatches are ignored, not fatal, so a spoofer cannot end the exchange | 1 | done |
| Hostile upstream responses (B2)             | Responses are checked before parsing (one question, section counts that fit the message), size-capped (4096 bytes over UDP) and fuzzed (`decode-response`). Extended rcodes are never sent to clients without EDNS | 1 | done |
| Slow or dead upstreams exhausting the server (B1, B2) | Per-attempt and total timeouts, failover with a back-off for failing upstreams, a cap on UDP queries in flight; queries beyond it are dropped | 1 | done |
| Cache poisoning (B2)                        | Only the CNAME chain answering the question and the records at its end are cached, never unrelated answer, authority or additional records; chains are capped at 16 and loops are refused; negative answers need an SOA for a zone containing the name and are cached for at most min(SOA TTL, SOA minimum); TTL clamps; DO and CD are part of the cache key | 1 | done |
| Cache memory exhaustion (B1, B2)            | A bounded number of entries (configurable, at most 1,000,000), answers with more than 32 records are not cached, oldest entries are evicted first, shards are chosen with a per-process random hash key | 1 | done |
| On-path tampering / snooping upstream (B2)  | DoT and DoH upstreams with rustls (TLS 1.2+, ring), certificates checked against the bundled Mozilla roots for an explicitly configured name; no bootstrap resolution; DoH requires HTTP/2, status 200, the DNS content type and caps bodies at 64 KiB ([ADR 0003](adr/0003-upstream-tls.md)) | 1 | done |
| DNS rebinding (B2)                          | Forwarded answers for names outside the configured private domains (`lan`, `home.arpa`, `internal`, `local` by default) lose their A and AAAA records with RFC 1918, carrier-NAT, loopback, link-local, unspecified or unique-local addresses (IPv4-mapped forms included), before caching. On by default | 1 | done |
| Abuse as a DoS amplifier / query floods (B1) | UDP rate limiting per client network (each IPv4 address and IPv6 /64 by default: 300 queries/s, bursts of 1000), applied before a query is resolved, so floods reach neither the cache nor the upstreams. Every second limited query gets an empty TC=1 answer no bigger than the query, so real clients retry over TCP and spoofed victims get no amplification. The table of client networks is bounded (65,536); when full, untracked networks share one bucket. Loopback is exempt (it cannot be spoofed from the network) | 1 | done |
| Another local process taking part of port 53 (B6) | `SO_REUSEPORT` is set only when several UDP sockets share an address (Linux); the kernel only lets sockets of the same user join, so goethite should run as its own user | 1 | done |
| Process compromise impact (B6)              | Sockets are bound before any thread starts; then goethite switches to `server.user` when started as root (no supplementary groups), empties its capability sets, sets `no_new_privs` and checks that root cannot be regained. The systemd unit in `deploy/systemd/` runs it as a dynamic user with only `CAP_NET_BIND_SERVICE` (given up after binding), a read-only file system except its state directory, private `/tmp` and devices, IP sockets plus Unix sockets (systemd notifications and upgrades) and a system call filter (`systemd-analyze security`: 1.7, "OK") | 1 | done |
| Hostile filter lists (B3)                   | Local files: at most 128 MiB per list, 4096-byte lines, 5,000,000 rules; unsupported and invalid lines are counted and skipped, never guessed at (no regex engine to exhaust); rules naming the root are refused; compiled off the async runtime and swapped in atomically, keeping the old filter if compiling fails; the parser and compiler are fuzzed (`parse-list`) and checked against a rule-by-rule reference | 1 | done |
| Hostile FilterLists data (B3)               | The directory is fetched by the node, never the browser, only when browsed: HTTPS through goethite's resolver, 4 MiB and 20 s per request, kept a day, one refresh at a time. Bounded parsers (fuzzed: `parse-filterlists`) ignore unknown fields, strip control characters, cap text and counts and keep only `https://` addresses; allowlists and unreadable syntaxes are left out. A list found there is added only after a person checks the filled-in form ([ADR 0018](adr/0018-list-sources.md)). The recommended lists' sizes are read the same way, when asked: the first 8 KiB of each, six at a time, kept a day, parsed only from comment lines and capped at twelve digits (fuzzed in `parse-filterlists`; [ADR 0022](adr/0022-recommended-list-catalog.md)) | 4 | done |
| Hostile services catalog (B3)               | Downloaded with the lists (HTTPS, goethite's resolver, the last good copy kept) and refused over 4 MiB or without services. A bounded parser (fuzzed: `parse-services`) ignores unknown fields, keeps valid, distinct IDs, strips control characters and caps services (1,024), rules per service (2,048) and rule length; rules go through goethite's rule parser and only blocking ones are kept. Compiled off the async runtime and swapped in atomically; a bad catalog keeps the current one ([ADR 0019](adr/0019-blocked-services.md)) | 4 | done |
| Hostile list downloads (B3)                 | HTTPS only (redirects too), certificates checked against the bundled roots, list hosts resolved through goethite's own upstreams; 128 MiB and two-minute limits; a download replaces the last good copy only if it holds rules and more rules than junk; copies written atomically and kept for offline starts | 1 | done |
| Unauthorized admin access (B4)              | Without an admin token the API answers loopback only and refuses to start on other addresses. With one, every request but the health check needs it; the config holds only its SHA-256 (the token is 256 random bits, so the hash can neither be reversed nor guessed), compared without early exit. Optional HTTPS with the operator's certificate; plain HTTP beyond loopback logs a warning. At most 64 connections, 10 s for the TLS handshake and headers, 1 MiB bodies, 30 s per request; specs reject unknown fields | 2 | done |
| Browser attacks on the API (B4)             | No CORS headers, so other sites' pages cannot read responses; the token travels in a header, not a cookie, so cross-site requests carry no credentials. Requests with an `Origin` from another site are refused, so even requests needing no preflight do nothing. Without a token, only loopback `Host` names are answered, so DNS rebinding a hostile name to 127.0.0.1 reaches nothing; with one, a rebinding page has no token. Every response sets a strict CSP, `X-Frame-Options: DENY`, `nosniff` and `no-referrer`; API answers are `no-store`. The checks are fuzzed (`request-checks`) ([ADR 0009](adr/0009-web-ui-serving.md)) | 2 | done |
| Unaccountable config changes                | Every change to the store is written in the same transaction as an audit entry (who, from where, before and after); the newest 100,000 entries are kept. The store file is created with mode 0600 and locked against a second process | 2 | done |
| XSS / injection in the web UI               | The UI is served under the API's strict CSP: no inline scripts or styles, no `eval`, no third-party origins, no data: fonts. The build inlines nothing and self-hosts its fonts; React escapes everything rendered and the UI never sets raw HTML. Its files hold no data; the API behind them needs the token. The token lives in the tab's `sessionStorage`, cleared on a 401 and on sign-out. The sign-in page only returns to paths on its own origin. `[api] web_ui = false` turns the UI off | 2 | done |
| XSS through `/api/docs`                     | `/api/docs` (Scalar) is off by default and answers loopback only; every file is built into the binary, never a CDN; scripts are `'self'` only, styles need a per-page nonce or a known hash (style attributes are allowed, see the web UI docs) | 4 | done |
| Query privacy in logs (B6)                  | The query log keeps 7 days and at most 1,000,000 entries by default, can anonymize clients to /24 and /56 or be turned off; statistics keep only hourly top-100 lists for 30 days; the store file is readable by goethite's user only. Logging is queued and drops (and counts) entries rather than blocking queries, and stored records are decoded with bounds checks (fuzzed: `decode-query-record`) | 2 | done |
| Malicious cluster peer (B5)                 | Config sync over TLS 1.3 with certificates from a private cluster CA in both directions; each node accepts only the configured peer's node name, so a certificate for another node or from another cluster is refused. Copies are validated as a whole, versioned (never older), schema-checked, audit-logged and applied off the DNS path; a replica that cannot reach the primary keeps its configuration ([ADR 0010](adr/0010-cluster-config-sync.md)) | 3 | done |
| Forged changes through the cluster channel (B5) | Only the primary runs forwarded changes, only configuration writes under `/api/v1/`, through the same validation and audit as any caller; the forwarding identity is an in-process extension that HTTP clients cannot set, and the replica's own API authentication decides who may forward. A compromised replica can make the changes an admin could, and is recorded as the node they came through | 3 | done |
| Cluster peer takes over the floating IP (B5) | VRRP version 3 has no authentication. Announcements are accepted only from the configured peer, with TTL 255 (same link), for the configured router ID and address; parsers are bounded and fuzzed (`parse-vrrp`, `parse-netlink`). A host on the same segment can still forge them, as it can forge ARP, so the network must be trusted (documented in the HA guide). The helper that moves the address runs as its own process with `CAP_NET_ADMIN` only; the DNS server never holds it ([ADR 0013](adr/0013-floating-ip.md)) | 3 | done |
| Hijacking an upgrade (B6)                   | The handover socket is created mode 0600 in the service's private runtime directory and removed once the new process connects; the parent sends sockets and keys only to the process it started, checked by `SO_PEERCRED`. The new process runs whatever binary is at goethite's path, as a restart would: protect `/usr/bin/goethite` like any binary root starts ([ADR 0012](adr/0012-zero-downtime-upgrades.md)) | 3 | done |
| Unsafe code adopting systemd's sockets (B6)  | One `unsafe` block, in the binary, takes the descriptors systemd passes: only when `LISTEN_PID` is this process, before any file is opened, each number exactly once, each checked to be a socket of the expected kind and address before use; every crate but this one and goethite-cluster forbids `unsafe` | 3 | done |
| Unsafe code addressing the gratuitous ARP (B5) | One `unsafe impl`, in goethite-cluster, hands the kernel a link-layer address (`struct sockaddr_ll`) for the `AF_PACKET` socket that announces the floating IP, since rustix has no type for one: `#[repr(C)]` in the kernel's field order and types, its size checked at compile time, borrowed for the whole system call. It runs only in the floating-IP helper (`goethite vrrp`), never in the DNS server | 3 | done |
| Filtering failure taking the network down   | Fail open by default: a store that cannot be opened is replaced by one in memory seeded from the config file (the file is left alone), an unbuildable filter leaves the previous one (or none at startup), and a failed check answers that query unfiltered; every case is reported in status, UIs and metrics. `[filter] on_failure = "closed"` refuses to start or answers SERVFAIL instead ([ADR 0011](adr/0011-fail-open.md)) | 3 | done |
| Poisoning through recursion (B2)            | Our own iterator believes a server only about its zone: answers within it, referrals strictly below it to zones containing the name, glue only for those name servers within it; everything else ignored, never cached (`classify`, fuzzed by `classify-response`). Every query to an authoritative server gets a fresh random port and ID, 0x20 case randomization (dropped per server only when it changes the case), the question matched exactly, TCP when truncated. Priming answers replace the root hints only with addresses ([ADR 0021](adr/0021-recursion.md)) | 4 | done |
| Resource exhaustion through recursion (B1, B2) | Per client query 64 queries and 6 s, nested lookups included; per name 32 referrals; name server address lookups 4 deep and 4 per zone; CNAME chains 16; 1,024 exchanges in flight; zone, address and server tables of 20,000 entries; QNAME minimisation capped at 10 queries per name (RFC 9156) | 4 | done |
| Leaking local names to the internet (B1)    | With recursion, special-use names and private reverse zones (RFC 6761, 6303, 7686, 7793, 8375) are answered locally and never sent to the root; QNAME minimisation shows each server only what it needs | 4 | done |
| Forged answers from authoritative servers or the path (B2) | With recursion, DNSSEC validation from built-in root trust anchors: signed answers must check (AD for clients that ask), bogus ones are SERVFAIL. Only signed proofs (NS without DS at a delegation, or NSEC3 opt-out) make a name insecure, so stripped or forged signatures, including a signature naming its own owner as the signer, are bogus, not insecure. Forwarded answers are not validated ([ADR 0023](adr/0023-dnssec-validation.md)) | 4 | done |
| Devices bypassing filtering (B1)            | The DNS leak test shows whether a device's lookups reach goethite (all, some or none), over which protocol and as which client, and when a forwarder hides devices; it detects, it does not enforce ([ADR 0024](adr/0024-dns-leak-test.md)) | 4 | partial |
| Abusing leak tests (B1)                     | Tests need the admin token; in memory, 32 tests of an hour with 64 lookups each; lookups for names a node did not hand out are ignored; test names (everything under `goethite.test`) are answered locally, never forwarded; the name parser is fuzzed (`parse-leak-probe`); the web UI's CSP allows images only from that reserved zone | 4 | done |
| Exhausting the validator (B1, B2)           | Per client query 64 signature checks (KeyTrap, CVE-2023-50387), 4 keys per key tag, 8 signatures per RRset, 8 proofs, 128 DNSSEC records kept per response; NSEC3 above 150 iterations is insecure without hashing (RFC 9276), 64 hashes per proof; running out is SERVFAIL but never remembered as bogus. The proof checks are fuzzed (`check-dnssec`) | 4 | done |
| Snooping of client queries on the network (B1) | DoT, DoH and DoQ listeners with rustls (ring; TLS 1.2 and 1.3, 1.3 only for QUIC; no 0-RTT) and the operator's certificate, reloadable on SIGHUP ([ADR 0015](adr/0015-encrypted-dns-serving.md), [ADR 0016](adr/0016-dns-over-quic.md)) | 4 | done |
| Guessing names from encrypted message sizes (B1, B2) | EDNS padding (RFC 7830) in RFC 8467's block sizes: answers to padded queries over DoT, DoH and DoQ fill 468-byte blocks, and goethite's queries to DoT and DoH upstreams 128-byte blocks; padding is zeros and stays within each transport's size limit. ODoH pads in its own layer. Timing and the number of queries are not hidden | 4 | done |
| Resource exhaustion through TLS, HTTP and QUIC (B1) | DoT, DoH and DoQ share the TCP connection limits (256 in total, 16 per client); 10 s for the handshake, 30 s idle; DoH heads of at most 64 KiB sent within 10 s, bodies of at most 65,535 bytes within the idle time, 64 HTTP/2 streams per connection; DoQ: 64 bidirectional streams and no unidirectional ones, a 256 KiB receive window, one message per stream, protocol errors close the connection. The request parsers are fuzzed (`parse-doh`, `parse-doq`). Encrypted queries are not rate limited per client yet (backlog) | 4 | partial |
| Spoofed QUIC handshakes filling connection slots (B1) | A DoQ client's address is validated with a Retry before its connection takes a slot, as TCP's handshake does; QUIC's anti-amplification limit bounds what goethite sends to an unvalidated address | 4 | done |
| Open resolver on the internet through DoT/DoH/DoQ (B1) | `require_client_id` refuses encrypted queries without a known client ID. Client IDs are names, not secrets: DoT and DoQ carry them in the clear in the TLS server name; the DoH path keeps them encrypted. Off by default, documented for internet-facing setups | 4 | done |
| The resolver learning who asks (B1)        | goethite can be an Oblivious DoH target (RFC 9230): through someone else's proxy it sees the query, not the client's address. Target keys are made from the system's random number generator, kept in memory only and rotated daily, so a later compromise does not decrypt recorded traffic; answers are padded to 468-byte blocks and never cacheable ([ADR 0020](adr/0020-oblivious-doh-target.md)) | 4 | done |
| Hostile ODoH messages (B1)                  | ODoH bodies of at most 65,572 bytes, read within the idle time; bounded parsers that refuse trailing bytes and non-zero padding, an HPKE decryption per message (X25519, the cost of a TLS handshake's key exchange or less), 401 for unknown keys and 400 for the rest. Parsers and decryption are fuzzed (`parse-odoh`) and checked against Cloudflare's test vectors. A proxy's queries share one per-client connection limit | 4 | done |
| Upstream learning client identity           | Upstreams see goethite's address, not its clients'. Sending goethite's own upstream queries over ODoH is backlog | 4 | partial |
| Tampered releases (B7)                      | Reproducible, signed builds. SBOM.                                                                  | 5     | planned |
| Residual design and implementation flaws    | External security review                                                                           | 5     | planned |
| Exploited process escaping its role (B6)    | Landlock and seccomp sandboxing                                                                    | 5     | planned |

## 5. Non-goals

goethite does **not** try to defend against:

- **A fully compromised host or root user.** Anyone with root on the node can read and change
  everything.
- **Anonymity from upstream resolvers** beyond what encrypted transports and ODoH provide. A
  forwarding resolver necessarily reveals queries to its upstream.
- **Clients that bypass goethite**, for example devices with hardcoded DoH/DoT resolvers or
  hardcoded IPs. Blocking that requires firewall policy outside goethite's scope.
- **Volumetric DDoS absorption** beyond rate limiting and resource bounds. goethite should degrade
  without crashing, but it cannot out-scale a flood.
- **Windows as a server platform.** It is not supported, so it is not hardened. macOS is for
  development only.
- **Perfect filtering.** Filter lists are third-party data. A list that misses a tracker is not a
  security vulnerability.

## 6. Open questions

- Query log defaults: should logging be off, anonymized or full by default? What is the default
  retention?
- How should filter list sources be authenticated beyond HTTPS? Pinned hashes, signatures, or
  neither?
- Cluster network assumptions: VRRP is as safe as its network segment (ADR 0013). Should goethite
  offer an authenticated election for shared networks, at the cost of interoperating with
  standard VRRP?
- Secrets storage: where do the admin token, mTLS keys and upstream credentials live, with what
  file permissions and rotation story?
- Fail-open versus fail-closed defaults: which one, and how is the choice surfaced to admins?
- Should the API ever be reachable without TLS on non-loopback addresses?
