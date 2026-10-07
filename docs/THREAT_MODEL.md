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

Today (Phase 1, milestone 3) goethite has UDP/TCP listeners, a built-in `goethite.test.` record,
forwarding to configured upstreams over DNS over TLS, DNS over HTTPS or plain DNS with failover,
and a cache. There is no filtering yet.

### Trust boundaries

| #  | Boundary                                      | Direction          | Notes                                                       |
| -- | --------------------------------------------- | ------------------ | ----------------------------------------------------------- |
| B1 | LAN clients → DNS listeners (UDP/TCP 53, later DoT/DoH/DoQ) | untrusted → node | Highest-volume, fully attacker-controlled input             |
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
| Memory-safety bugs                          | `unsafe_code = "forbid"` workspace-wide, plus `#![forbid(unsafe_code)]` in proto/filter/resolver   | 0     | done    |
| Parser bugs found too late                  | cargo-fuzz targets `decode_query` (round-trip property) and `parse_name` (display/parse property), weekly CI fuzz run, proptest round-trip and garbage-input tests | 0 | done |
| Malformed or abusive EDNS data (B1)         | EDNS options are checked before parsing: options running past the OPT record, COOKIE options of the wrong length and inconsistent client-subnet options get FORMERR. Zone transfers are refused and meta query types get FORMERR | 0 | done |
| Reflection / response loops (B1)            | Messages with QR=1 (responses) are dropped, never answered                                         | 0     | done    |
| Oversized UDP responses / amplification     | UDP responses fit the client's limit (512 without EDNS, at most the advertised EDNS size). goethite advertises 1232 and sets TC when truncating. | 0 | done |
| TCP resource exhaustion (B1)                | TCP connection cap, idle timeout, 2-byte length framing (RFC 7766)                                 | 0     | done    |
| One client holding every TCP slot (B1)      | Per-client connection limits, closing the oldest idle connection when full, a shorter first-byte timeout under load (RFC 7766 §6.2.3). Today a single host that opens `max_tcp_connections` idle connections blocks TCP (and TC=1 fallback) for everyone | 1 | planned |
| Accidental exposure of a dev build          | Development default listens on `127.0.0.1:15353`                                                   | 0     | done    |
| Config typos silently changing behaviour    | Unknown TOML fields are rejected. The config file size is bounded.                                 | 0     | done    |
| Supply chain (B7)                           | `cargo deny` (licenses, advisories, bans, sources) and `cargo audit` in CI for the main and the fuzz workspace. GitHub Actions pinned to commit SHAs. Minimal workflow permissions. | 0 | done |
| Crash details disclosed by public CI fuzzing | Crash artifacts are kept 7 days; the trade-off is documented in SECURITY.md. Fuzzing moves to a private setup before the first release | 0 / 5 | partial |
| Unknown threats                             | This threat model                                                                                  | 0     | done    |
| Off-path spoofed upstream answers (B2)      | A fresh UDP socket per exchange with an OS-randomized source port, connected to the upstream; random 16-bit IDs; 0x20 case randomization; a response is accepted only if its ID, opcode and question in exactly the sent case match. Mismatches are ignored, not fatal, so a spoofer cannot end the exchange | 1 | done |
| Hostile upstream responses (B2)             | Responses are checked before parsing (one question, section counts that fit the message), size-capped (4096 bytes over UDP) and fuzzed (`decode_response`). Extended rcodes are never sent to clients without EDNS | 1 | done |
| Slow or dead upstreams exhausting the server (B1, B2) | Per-attempt and total timeouts, failover with a back-off for failing upstreams, a cap on UDP queries in flight; queries beyond it are dropped | 1 | done |
| Cache poisoning (B2)                        | Only the CNAME chain answering the question and the records at its end are cached, never unrelated answer, authority or additional records; chains are capped at 16 and loops are refused; negative answers need an SOA for a zone containing the name and are cached for at most min(SOA TTL, SOA minimum); TTL clamps; DO and CD are part of the cache key | 1 | done |
| Cache memory exhaustion (B1, B2)            | A bounded number of entries (configurable, at most 1,000,000), answers with more than 32 records are not cached, oldest entries are evicted first, shards are chosen with a per-process random hash key | 1 | done |
| On-path tampering / snooping upstream (B2)  | DoT and DoH upstreams with rustls (TLS 1.2+, ring), certificates checked against the bundled Mozilla roots for an explicitly configured name; no bootstrap resolution; DoH requires HTTP/2, status 200, the DNS content type and caps bodies at 64 KiB ([ADR 0003](adr/0003-upstream-tls.md)) | 1 | done |
| DNS rebinding                               | Rebinding protection: drop private/loopback answers for public names                               | 1     | planned |
| Abuse as a DoS amplifier / query floods     | Response rate limiting (RRL)                                                                       | 1     | planned |
| Process compromise impact (B6)              | Drop privileges after binding port 53. Hardened systemd unit (no new privileges, `CAP_NET_BIND_SERVICE` only, protected paths). | 1 | planned |
| Hostile filter lists (B3)                   | Download size limits, rule count and length limits, validation before use, atomic swap of compiled lists (old list kept on failure) | 1 | planned |
| Unauthorized admin access (B4)              | Admin token. The API binds to loopback until a token is configured.                                | 2     | planned |
| Unaccountable config changes                | Audit log for every config change                                                                  | 2     | planned |
| XSS / injection in the web UI               | Strict CSP with no inline scripts. Bundled assets, never a CDN. `/api/docs` off by default and loopback-only. | 2 | planned |
| Query privacy in logs (B6)                  | Query log retention limits, client anonymization options, bounded storage                          | 2     | planned |
| Malicious cluster peer (B5)                 | mTLS-authenticated config sync. VRRP authentication is weak by design, so the cluster network must be trusted or isolated (documented). | 3 | planned |
| Filtering failure taking the network down   | Fail-open option                                                                                   | 3     | planned |
| Forged answers from upstream (B2)           | Recursion with full DNSSEC validation                                                              | 4     | planned |
| LAN snooping of client queries (B1)         | DoH / DoT / DoQ server listeners                                                                   | 4     | planned |
| Upstream learning client identity           | ODoH (Oblivious DoH)                                                                               | 4     | planned |
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
- Rebinding protection defaults: which ranges, and how are allowlists for split-horizon setups
  handled?
- Cluster network assumptions: is a dedicated VLAN required, and how do we secure VRRP on shared
  networks?
- Secrets storage: where do the admin token, mTLS keys and upstream credentials live, with what
  file permissions and rotation story?
- Fail-open versus fail-closed defaults: which one, and how is the choice surfaced to admins?
- Should the API ever be reachable without TLS on non-loopback addresses?
