# Competitor features: AdGuard Home, Pi-hole and Numa

What AdGuard Home, Pi-hole and Numa offer as of 2026-10-09, set against goethite v0.5.0, as input
for planning 1.0. The three inventories at the end come from primary sources only: official
documentation, source code at pinned commits, release notes and each project's own issue tracker
or forum. Every claim in them links to its source. The summary, the matrix and the gap list
condense those inventories and goethite's own [docs](https://nxplain-sh.github.io/goethite/).

| Product | Version compared | Released | Licence, language |
| --- | --- | --- | --- |
| AdGuard Home | v0.107.79 (beta: v1.0.0-b.1, 2026-09-30) | 2026-08-18 | GPL-3.0, Go |
| Pi-hole | Core v6.4.3, FTL v6.7.1, Web v6.6 | 2026-07-06, 2026-09-19 | EUPL-1.2, C (FTL embeds dnsmasq), Bash, Lua |
| Numa | v0.24.1 | 2026-10-03 | MIT, Rust |
| goethite | v0.5.0 | 2026-10-09 | MIT OR Apache-2.0, Rust |

Contents: [Summary](#summary) · [Feature matrix](#feature-matrix) ·
[Gaps for goethite](#gaps-for-goethite) · [AdGuard Home](#adguard-home) · [Pi-hole](#pi-hole) ·
[Numa](#numa)

## Summary

- **None of the three has high availability, and users ask for it more than anything else.**
  "Run 2 instances for redundancy" is AdGuard Home's most-upvoted open issue (#573, 154 votes,
  open since 2019); HA is Pi-hole's most-voted forum request (193 votes, open since 2017), and
  its staff have "no plans" for it; Numa's README says "no clustering, no config sync". Sync for
  the first two comes only from third-party tools (adguardhome-sync, nebula-sync). goethite's
  Raft cluster with a witness, its floating IP and its upgrades without dropped queries have no
  counterpart.
- **AdGuard Home is the filtering benchmark, and rule syntax is where goethite trails it most.**
  AdGuard Home runs regex rules and seven modifiers (`$client`, `$ctag`, `$denyallow`,
  `$dnstype`, `$dnsrewrite`, `$important`, `$badfilter`), filters answers by CNAME and by IP,
  and offers safe search for 7 engines and hash-prefix safe browsing. goethite skips regex and
  every modifier today. This is the largest gap against AGENTS.md's goal of matching AdGuard
  Home on everyday filtering.
- **goethite leads on policy structure.** AdGuard Home has no client groups (#2527), cannot give
  a client its own blocklists (#8029), and schedules only blocked services, one window per day.
  Pi-hole has groups but no schedules, safe search or blocked services. Numa has per-CIDR rules
  in its config file only.
- **Only goethite validates DNSSEC by default, and only goethite and Numa recurse.** AdGuard Home
  forwards only and trusts the upstream's AD bit (#790 and #1579 are open). Pi-hole validates
  through dnsmasq when turned on (off by default) and recurses only through its Unbound guide.
  Numa validates only in recursive mode, and only when turned on.
- **The others share resolver conveniences goethite lacks:** per-domain upstreams (all three),
  serving stale answers (all three), prefetching (Numa), and DoQ, DNSCrypt and HTTP/3 upstreams
  (AdGuard Home).
- **Encrypted DNS:** AdGuard Home serves DoT, DoH (including HTTP/3), DoQ and DNSCrypt. The
  released Pi-hole serves and forwards none of them; DoT and DoH are on its development branch
  for a v7 with no date. Numa serves DoT, and DoH over HTTP/1.1 only. Only goethite serves
  Oblivious DoH as a target; Numa is an ODoH client and relay.
- **No competitor sandboxes itself or exports Prometheus metrics.** No seccomp or Landlock code
  was found in any of the three, and Prometheus is an open request at AdGuard Home (#516) and
  only a community exporter for Pi-hole. In 2026, Pi-hole's FTL published 17 advisories (13
  high) and AdGuard Home fixed a critical authentication bypass (CVE-2026-32136). Release
  integrity ranges from GPG signatures (AdGuard Home) to SHA-1 (Pi-hole) and SHA-256 (Numa)
  checksums.
- **Numa competes on a different ground.** It is built for one developer machine: `.numa` names
  for local services behind a reverse proxy with a local CA, plus basic filtering. Its
  developer features are out of goethite's 1.0 scope (AGENTS.md), but some resolver ideas are
  worth borrowing: hedged upstream requests, serve-stale with prefetch, and a warm list of names
  kept fresh.

## Feature matrix

"No" means not supported, according to the product's docs and source; the inventories give the
evidence. Cells with an issue number name the open request. "Not checked" means the research did
not cover it.

### Filtering

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| Hosts files and domain lists | Yes | Yes | Yes | Yes |
| `\|\|name^` rules and `@@` exceptions | Yes | Only `\|\|name^` and `@@\|\|name^` | Reduced to bare names; `@@` lines never match | Yes |
| Regex rules | Yes (RE2) | Yes, with `;querytype=`, `;invert`, `;reply=` | No | No |
| Rule modifiers | 7 (`$client`, `$ctag`, `$denyallow`, `$dnstype`, `$dnsrewrite`, `$important`, `$badfilter`) | No | No (stripped) | No |
| Hosts lines with a real address as the answer | Yes | No (address ignored) | No | No (skipped) |
| CNAME uncloaking | Yes, and answer IPs | Yes | No | Yes |
| Blocked answer | 5 modes, including a custom IP | 5 modes, including an IP and NODATA | `0.0.0.0` / `::`, fixed | Null IP, NXDOMAIN or REFUSED |
| Extended DNS Error on blocked answers | No ("not yet") | Yes, EDE 15 by default | Not checked | No |
| Safe search | 7 engines | No | No | 4 engines |
| Blocked services | 142 services | No | No | Yes, AdGuard's catalog |
| Safe browsing via a cloud lookup | Yes, hash prefixes to AdGuard | No | No | No |
| Rebinding protection | As a filter list | Not by default | Opt-in | On by default |
| Firefox canary, iCloud Private Relay | Not checked | Yes, on by default | Not checked | No |
| List catalog | 64 vetted lists | Not checked | One default list | 36 recommended, plus the FilterLists directory |
| List updates | 0 to 8760 hours | Weekly cron job, not configurable | Every 24 hours | 1 to 168 hours |
| Rule tester ("why is this blocked") | Yes | List search; `regex-test` in the CLI | Yes | No |

### Clients and policy

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| Groups | No (#2527) | Yes | No | Yes |
| Lists per client or group | No (#8029); rules via `$client` or `$ctag` | Per group | Inline names per CIDR rule | Per group |
| Schedules | Blocked services only, one window a day | No | No | Lists and blocked services, weekly windows |
| Client identification | IP, CIDR, MAC (with its own DHCP), client ID | IP, CIDR, MAC, hostname, interface, ECS | IP, CIDR | IP, CIDR, client ID |
| Upstreams per client | Yes | No | No | No |
| Access control | Allowed and disallowed clients | Listening modes | `allow_from` | Allowed and blocked clients |
| Rate limiting | 20 queries/s per /24 or /56, dropped | 1000 per minute per client, REFUSED | No (#378) | Per client, every transport |

### Resolution

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| Upstream protocols | UDP, TCP, DoT, DoH (incl. HTTP/3), DoQ, DNSCrypt | Plain DNS (DoT, DoH on development) | UDP, TCP, DoT, DoH, ODoH | UDP, TCP, DoT, DoH |
| Upstreams per domain | Yes | Conditional forwarding, dnsmasq lines | Yes, and found automatically | No |
| Recursion | No (#790) | Through Unbound | Yes | Yes |
| DNSSEC validation | No: trusts the upstream's AD bit | Opt-in (dnsmasq) | Opt-in, recursive mode only | On by default (recursion) |
| Serve stale | Yes (optimistic cache) | Yes (cache optimizer) | Yes, RFC 8767 | No |
| Prefetch | No (#1259) | Not checked | Yes | No |
| Local records | A, AAAA, CNAME, wildcards; more types via `$dnsrewrite` | A, AAAA, CNAME; no wildcards | A, AAAA, CNAME, PTR, NS, MX; wildcards | A, AAAA, CNAME; wildcards |
| 0x20 case randomization | Not documented | Not checked | No | Yes |
| EDNS Client Subnet | Sent upstream | Read as the client's identity | No | No |
| AAAA filtering, DNS64 | Yes | Not checked | AAAA filtering | No |

### Encrypted DNS for clients

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| DoT | Yes | No (development) | Yes | Yes |
| DoH | HTTP/1.1, 2, 3 | No (development) | HTTP/1.1, loopback by default | HTTP/1.1, 2 |
| DoQ | Yes | No (open PR) | No | Yes |
| DNSCrypt | Yes | No | No | No |
| Oblivious DoH | No (#2406) | No | Client and relay | Target |
| Behind a reverse proxy | Trusted proxies; no PROXY protocol (#2798) | No | PROXY protocol v2 | No |
| Apple configuration profiles | Yes, unsigned | No | Yes, unsigned | No |

### Operations and interfaces

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| HA, config sync | No (#573) | No; third-party tools | No | Raft, witness, VRRP floating IP |
| Changes without a restart | UI and API; file edits need a stop and start | 62 of 167 keys restart FTL | Restart for config changes | Store settings apply live; upgrades without dropped queries |
| API description | Hand-written OpenAPI | OpenAPI, embedded | None | OpenAPI generated from the code, breaking changes checked |
| Prometheus metrics | No (#516) | No; JSON metrics | No | Yes |
| Query log | JSON file, 90 days | SQLite, 91 days | Last 1,000, in memory | 7 days, up to 1,000,000 entries |
| Authentication | Users with bcrypt hashes, no roles, no 2FA | Password, one app password, TOTP | Token; loopback exempt | One admin token |
| Backup and restore | No (#1147) | Teleporter archive | No | No file export; `goethite migrate` |
| Terminal UI | Third-party | PADD | No | `goethite tui` |
| DHCP server | Yes (v4, v6) | Yes (dnsmasq) | No | No |
| Home Assistant integration | Yes, maintained by Home Assistant | Yes, a guide over the API | Not checked | No |
| Platforms | Linux, macOS, Windows, FreeBSD, OpenBSD; MIPS and more | Linux | Linux, macOS, Windows | Linux (amd64, arm64) |

### Security and supply chain

| Feature | AdGuard Home | Pi-hole | Numa | goethite |
| --- | --- | --- | --- | --- |
| Privileges | Drops to `os.user`, or `setcap` | User `pihole` with 7 capabilities | systemd `DynamicUser`; root on macOS and in Docker | Drops after binding |
| Sandbox | No | No | No | Landlock and seccomp |
| Release integrity | GPG signatures; reproducible (claimed) | SHA-1 checksums; unsigned image | SHA-256 checksums | Reproducible, Sigstore attestations, SBOMs |
| Published performance numbers | None | None beyond a 2017 anecdote | Micro-benchmarks and `dig` samples | dnsperf runs in `bench/` |

## Gaps for goethite

Features at least one competitor has and goethite lacks, with where each stands in
[`BACKLOG.md`](BACKLOG.md). The first group is what "match AdGuard Home on everyday filtering"
(AGENTS.md) asks for; the rest are ranked by how many competitors have them and how often their
users ask.

### Filtering parity with AdGuard Home

| Gap | Who has it | Backlog |
| --- | --- | --- |
| Rule modifiers: `$important`, `$badfilter`, `$client`, `$dnstype`, `$denyallow` | AdGuard Home | Yes, "More filter syntax" |
| `$ctag` and `$dnsrewrite` (answers, NXDOMAIN and other RCODEs) | AdGuard Home | `$dnsrewrite=NXDOMAIN` only |
| Regex rules | AdGuard Home, Pi-hole | Yes |
| Hosts lines with a real address, as local answers | AdGuard Home | Yes |
| Answer filtering by IP (`\|10.*`-style rules) | AdGuard Home | No |
| Safe search for Ecosia, Pixabay and Yandex | AdGuard Home | No |
| A rule tester: which rule blocks a name, for which client | AdGuard Home, Numa; Pi-hole (list search) | No |
| A custom IP as the blocked answer | AdGuard Home, Pi-hole | No |

### Resolver

| Gap | Who has it | Backlog |
| --- | --- | --- |
| Upstreams per domain, while forwarding as well as recursing | All three | Recursing only |
| Serve stale and prefetch (RFC 8767) | All three serve stale; Numa prefetches | Yes |
| Extended DNS Errors, at least EDE 15 for blocked answers | Pi-hole | Yes |
| Firefox canary and iCloud Private Relay answers | Pi-hole | Canary only |
| DoQ and HTTP/3 upstreams | AdGuard Home | No |
| Hedged upstream requests (a second query after a delay) | Numa | No |
| Upstreams per client or group | AdGuard Home | No |
| AAAA filtering, DNS64 | AdGuard Home; Numa (AAAA) | No |
| EDNS Client Subnet as the client's identity, behind another forwarder | Pi-hole | No |

### Serving, operations and interfaces

| Gap | Who has it | Backlog |
| --- | --- | --- |
| DoH behind a reverse proxy (trusted proxies) | AdGuard Home | Yes |
| PROXY protocol on listeners | Numa; asked of AdGuard Home (#2798, 95 votes) | No |
| Several users or scoped tokens, and TOTP | AdGuard Home (several users, no roles); Pi-hole (app password, TOTP) | Scoped tokens only |
| Backup and restore of the whole configuration | Pi-hole (Teleporter); asked of AdGuard Home (#1147) | No |
| Apple configuration profiles for DoT and DoH | AdGuard Home, Numa | No |
| Client names from reverse DNS, ARP or DHCP leases | AdGuard Home, Pi-hole | No |
| Leaving chosen names or clients out of the query log | AdGuard Home | No |
| Flushing the cache from the API | AdGuard Home, Numa; Pi-hole (`pihole reloaddns`) | No |
| Home Assistant integration | AdGuard Home, Pi-hole (both kept outside the projects) | No |
| DHCP server | AdGuard Home, Pi-hole | No; a scope decision for 1.0 |
| Platforms beyond Linux | AdGuard Home, Numa | Out of scope (AGENTS.md) |

Out of scope for 1.0 by AGENTS.md, and only in Numa: `.numa` local service names, the reverse
proxy and local CA behind them, and LAN discovery between instances.

### What their users ask for that goethite already has

The most-requested open items at AdGuard Home and Pi-hole that goethite ships: HA (#573 and
Pi-hole's top request), Prometheus metrics (#516), recursion (#790), DNSSEC validation (#1579),
client groups (#2527), per-client lists (#8029), Oblivious DoH (#2406), timed lists (#1203,
Pi-hole's timed blocking), and an audit log (Pi-hole). They are worth naming on the website's
comparison and migration pages.

## AdGuard Home

As of 2026-10-09, AdGuard Home v0.107.79 (2026-08-18)

Scope and pinning. Source links point at fixed revisions so line numbers stay valid:

- `AdguardTeam/AdGuardHome` master at commit `8dedd32` (2026-10-08), written below as "master"; tags `v0.107.79` (latest stable) and `v1.0.0-b.1` (latest pre-release) ([repo at 8dedd32](https://github.com/AdguardTeam/AdGuardHome/tree/8dedd3278542b45ea21994e24422f5cc53e14b8f); [tags](https://github.com/AdguardTeam/AdGuardHome/tags)).
- Knowledge Base (KB) pages at `adguard-dns.io/kb/adguard-home/…`, read from their source repo `AdguardTeam/KnowledgeBaseDNS` at commit `562a1db` (2026-10-02), with anchors checked against the rendered pages on 2026-10-09 ([KnowledgeBaseDNS at 562a1db](https://github.com/AdguardTeam/KnowledgeBaseDNS/tree/562a1dbbd3d2e0bd8ad456ee7458d91b80e8071f/docs/adguard-home)).
- The GitHub wiki marks itself outdated and points to the KB, so this report uses the KB ([wiki Home](https://github.com/AdguardTeam/AdGuardHome/wiki)).
- "Not supported" means not in the docs and not found in the source; where an open issue tracks it, the issue is cited.
- In nested lists, a source on a parent bullet covers its sub-bullets, and a label-only parent bullet (ending in a colon) takes its sources from its sub-bullets.

### 1. Version, release status, licence, language, platforms, install

- Latest stable release: **v0.107.79**, published 2026-08-18 ([release v0.107.79](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.79); [CHANGELOG L68](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L68)).
- Latest pre-release: **v1.0.0-b.1**, published 2026-09-30. It is the first beta of the "new UI and versioning scheme" and follows v0.108.0-b.91 (2026-09-28) ([release v1.0.0-b.1](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v1.0.0-b.1); [release v0.108.0-b.91](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.108.0-b.91)).
- The v0.108.0 line only ever shipped betas (up to b.91). Edge (nightly) builds are now numbered `v1.0.0-a.N`, counting commits from `v0.108.0-b.89` ([version.sh at v1.0.0-b.1 L87-L97](https://github.com/AdguardTeam/AdGuardHome/blob/v1.0.0-b.1/scripts/make/version.sh#L87-L97)).
- The CHANGELOG's "Unreleased" section has placeholder headings for v1.0.0 ("TBA") and v0.107.80 ("2026-09-03 (APPROX.)"). The pending changes include dropping macOS 13 Ventura support (Go 1.27) ([CHANGELOG L7-L51](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L7-L51)).
- 2026 stable cadence: v0.107.72 (02-19), .73 (03-10), .74 (04-16), .75 (05-19), .76 (05-21), .77 (06-01), .78 (07-13), .79 (08-18) ([CHANGELOG L68-L319](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L68-L319)).
- Release channels:
  - `release`, `beta` ("usually released every two weeks or more often") and `edge` (daily, from the development branch) ([README L320-L346](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L320-L346)).
  - Edge moved to the new UI in v0.107.79 ([CHANGELOG L90](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L90)), and beta moved in v1.0.0-b.1 ([release v1.0.0-b.1](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v1.0.0-b.1)).
- The two web UIs:
  - At v0.107.79 the `release` and `beta` pipelines build the legacy UI from `client/` (React 16), and `edge` builds `client_v2` ([bamboo-specs/release.yaml at v0.107.79 L8-L13](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/bamboo-specs/release.yaml#L8-L13); [L294-L315](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/bamboo-specs/release.yaml#L294-L315); [client/package.json](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/package.json)).
  - `client_v2` is Solid.js and is described as the "next-generation AdGuard Home web UI" ([client_v2/package.json](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client_v2/package.json); [client_v2/DEVELOPMENT.md](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client_v2/DEVELOPMENT.md)).
- Licence: GPL-3.0 ([LICENSE.txt](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/LICENSE.txt)).
- Language:
  - The backend is Go (`go 1.27.1` on master). It is built on AdGuard's own `dnsproxy`, `urlfilter` and `dnscrypt` libraries plus `miekg/dns`, `quic-go` and `bbolt` ([go.mod L1-L45](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/go.mod#L1-L45)).
  - The frontend is TypeScript ([client/package.json](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/package.json)).
  - The README says AdGuard Home shares much of its code with AdGuard's public DNS service ([README L44](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L44)).
- Official binary archives, per CPU architecture (also on `static.adguard.com`), with GPG `.sig` files inside the archives and a `checksums.txt` per release ([KB Platforms › packaged releases](https://adguard-dns.io/kb/adguard-home/platforms/#packaged-releases); [release v0.107.79 assets](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.79)):
  - macOS: amd64, arm64.
  - FreeBSD: 386, amd64, arm64, armv5, armv6, armv7.
  - Linux: 386, amd64, arm64, armv5, armv6, armv7, mips, mipsle, mips64, mips64le (all MIPS builds softfloat), ppc64le, riscv64.
  - OpenBSD: amd64, arm64.
  - Windows: 386, amd64, arm64.
- Install script:
  - Fetched with `curl`, `wget` or `fetch`. Options are `-c <channel>`, `-r` (reinstall), `-u` (uninstall) and `-v` (verbose) ([README L72-L99](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L72-L99)).
  - `-o <dir>` sets the install directory ([KB FAQ › Fedora](https://adguard-dns.io/kb/adguard-home/faq/#fedora)).
- Manual install:
  - Extract the archive and run `./AdGuardHome -s install` to register a system service. `-s uninstall|start|stop|restart|status` also exist ([KB Getting started › installation](https://adguard-dns.io/kb/adguard-home/getting-started/#installation); [› service](https://adguard-dns.io/kb/adguard-home/getting-started/#service)).
  - On Fedora, install into `/usr/local/bin` (SELinux). On macOS 10.15+, the working directory must be under `/Applications` ([KB Getting started › notes](https://adguard-dns.io/kb/adguard-home/getting-started/#notes)).
- Docker image `adguard/adguardhome`:
  - Architectures: amd64, 386, arm64, armv6, armv7, ppc64le ([KB Platforms › docker](https://adguard-dns.io/kb/adguard-home/platforms/#docker)).
  - Alpine base. `/opt/adguardhome/{conf,work}` volumes. Runs with `--no-check-update` ([docker/build.Dockerfile L3-L68](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/docker/build.Dockerfile#L3-L68)).
  - Needs `--network host` to see real client IPs and to run DHCP ([KB Docker › client IPs](https://adguard-dns.io/kb/adguard-home/docker/#client-ips); [› dhcp](https://adguard-dns.io/kb/adguard-home/docker/#dhcp)).
  - The image has no `HEALTHCHECK`. The KB recommends building your own image that queries `healthcheck.adguardhome.test` and expects `NODATA` ([KB Docker › health-check](https://adguard-dns.io/kb/adguard-home/docker/#health-check)).
- Snap `adguard-home`: amd64, 386, arm64, armv7 ([KB Platforms › snap](https://adguard-dns.io/kb/adguard-home/platforms/#snap)), with `strict` confinement ([snap/snap.tmpl.yaml L15-L16](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/snap/snap.tmpl.yaml#L15-L16)).
- Updates:
  - The UI shows an "Update now" button. The old binary and config are kept in `backup/`. `./AdGuardHome --update` updates from the CLI ([KB Getting started › update](https://adguard-dns.io/kb/adguard-home/getting-started/#update)).
  - Self-update is disabled for Docker, Home Assistant and Snap ([KB Getting started › update](https://adguard-dns.io/kb/adguard-home/getting-started/#update)).
- Unofficial packages named in the KB: Home Assistant add-on (@frenck), OpenWrt LuCI app (@kongfl888), Arch AUR, Cloudron, ZimaOS ([KB Getting started › other](https://adguard-dns.io/kb/adguard-home/getting-started/#other)).
- The README adds more third-party projects and says they are "not affiliated with AdGuard": a Chocolatey package, an Asuswrt-Merlin installer, and "AdGuard Home on GLInet routers" by GL.iNet ([README L367-L397](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L367-L397)).
- Router firmware:
  - No official router package ([KB Platforms › packaged releases](https://adguard-dns.io/kb/adguard-home/platforms/#packaged-releases); [KB Getting started › other](https://adguard-dns.io/kb/adguard-home/getting-started/#other)).
  - The binary has a `--glinet` "GL-Inet compatibility mode" ([KB Configuration › command-line](https://adguard-dns.io/kb/adguard-home/configuration/#command-line)).
  - The wiki links an OpenWrt-wiki install guide ([wiki Home](https://github.com/AdguardTeam/AdGuardHome/wiki)).
- Platform limitations:
  - DHCP is not supported on Windows ([KB DHCP › prerequisites](https://adguard-dns.io/kb/adguard-home/dhcp/#prerequisites)).
  - The statistics store needs `mmap(2)`, so some file systems are unsupported ([KB Getting started › limitations](https://adguard-dns.io/kb/adguard-home/getting-started/#limitations)).

### 2. Filtering

#### Lists and rule sources

- Three list formats are accepted: Adblock-style (a subset), `/etc/hosts`-style, and domains-only ([KB Syntax › introduction](https://adguard-dns.io/kb/general/dns-filtering-syntax/#introduction)).
- Default lists: "AdGuard DNS filter" (enabled) and "AdAway Default Blocklist" (disabled), both served from HostlistsRegistry ([config.go L347-L357](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L347-L357)).
- The UI offers a generated catalogue of 64 vetted lists from HostlistsRegistry `filters.json`, in 4 categories: general 15, other 15, regional 17, security 17 ([client/src/helpers/filters/filters.ts](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/src/helpers/filters/filters.ts); [scripts/vetted-filters/main.go L25](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/scripts/vetted-filters/main.go#L25)).
- Blocklists, allowlists (`whitelist_filters`, shown as "DNS allowlists") and custom rules (`user_rules`) are configured separately ([KB Configuration › filters](https://adguard-dns.io/kb/adguard-home/configuration/#filters); [› whitelist-filters](https://adguard-dns.io/kb/adguard-home/configuration/#whitelist-filters); [› user-rules](https://adguard-dns.io/kb/adguard-home/configuration/#user-rules)).
- Lists can be URLs or local files. Since v0.107.53 (fix for CVE-2024-36814), local files must match the `filtering.safe_fs_patterns` globs; the default is `$DATA_DIR/userfilters/*` ([CHANGELOG L906-L934](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L906-L934)).
- List download size is capped by `filtering.max_http_size`, default 256 MB, since v0.107.78 ([rulelist.go L24](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/rulelist/rulelist.go#L24); [CHANGELOG L132-L146](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L132-L146)).
- Update interval:
  - UI choices: off, 1, 12, 24, 72, 168 h ([constants.ts L188](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/src/helpers/constants.ts#L188)).
  - Since v0.107.78 the config file accepts any whole number of hours from 0 to 8760 ([CHANGELOG L142](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L142)).
  - Default: 24 h ([config.go L364](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L364)).
- `!#include` in lists: not supported; [#2173](https://github.com/AdguardTeam/AdGuardHome/issues/2173) is open in the v0.108.0 milestone ([#2173](https://github.com/AdguardTeam/AdGuardHome/issues/2173)).

#### Rule syntax and modifiers

- Adblock-style grammar: `["@@"] pattern ["$" modifiers]`, with special characters `*`, `||`, `^` and `|` ([KB Syntax › adblock-style](https://adguard-dns.io/kb/general/dns-filtering-syntax/#adblock-style-syntax); [› special characters](https://adguard-dns.io/kb/general/dns-filtering-syntax/#special-characters)).
- Comment lines start with `!` or `#` ([KB Syntax › comments](https://adguard-dns.io/kb/general/dns-filtering-syntax/#comments)).
- Regex rules (`/regex/`):
  - Supported ([KB Syntax › regular expressions](https://adguard-dns.io/kb/general/dns-filtering-syntax/#regular-expressions)).
  - urlfilter compiles them with Go's standard `regexp` package (RE2 syntax), but the KB links to MDN's JavaScript regex guide ([urlfilter rules/network.go L586](https://github.com/AdguardTeam/urlfilter/blob/347285f3f046958ed97d0fcf58da20b1b49be101/rules/network.go#L586)).
- If a rule uses a modifier the engine does not know, the whole rule is ignored, so browser lists such as EasyList do not cause false positives ([KB Syntax › rule modifiers](https://adguard-dns.io/kb/general/dns-filtering-syntax/#rule-modifiers)).
- Modifiers that work in AdGuard Home: `$client`, `$denyallow`, `$dnstype`, `$dnsrewrite`, `$important`, `$badfilter`, `$ctag`. `$respgeo` is documented as "AdGuard DNS only" ([KB Syntax › respgeo](https://adguard-dns.io/kb/general/dns-filtering-syntax/#respgeo-modifier)).
- `$client`:
  - Matches an IP, a CIDR or a persistent client's name; `~` excludes, and quotes and backslash escapes are supported ([KB Syntax › client](https://adguard-dns.io/kb/general/dns-filtering-syntax/#client-modifier)).
  - ClientIDs are not accepted; use the client's name instead ([KB Syntax › client](https://adguard-dns.io/kb/general/dns-filtering-syntax/#client-modifier)).
- `$denyallow` excludes domains from a blocking rule, e.g. `*$denyallow=com|net` ([KB Syntax › denyallow](https://adguard-dns.io/kb/general/dns-filtering-syntax/#denyallow-modifier)).
- `$dnstype`:
  - Matches the request type or the response RR type, with inclusion or `~` exclusion ([KB Syntax › dnstype](https://adguard-dns.io/kb/general/dns-filtering-syntax/#dnstype-modifier)).
  - **Disagreement:** the KB says response-type matching arrived "in v0.108.0", a version that never had a stable release. The v0.107.79 source already checks each answer record against its own type ([filter.go at v0.107.79 L116-L145](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/internal/dnsforward/filter.go#L116-L145)).
- `$dnsrewrite` ([KB Syntax › dnsrewrite](https://adguard-dns.io/kb/general/dns-filtering-syntax/#dnsrewrite-modifier)):
  - Takes priority over all other rules.
  - Short form: an IP, a hostname or an RCODE keyword. Full form: `RCODE;RRTYPE;VALUE`.
  - Supported RR types: A, AAAA, CNAME (resolved and added to the answer), PTR, MX, TXT, SRV, HTTPS and SVCB. For HTTPS and SVCB, only single, contiguous parameter values are accepted.
  - RCODE keywords give empty answers: NXDOMAIN, REFUSED, NOERROR.
  - `@@…$dnsrewrite` exception rules disable rewrites.
- `$important` raises a rule above exception rules. `$badfilter` disables the rule it names, but does not work on hosts-style rules ([KB Syntax › important](https://adguard-dns.io/kb/general/dns-filtering-syntax/#important-modifier); [› badfilter](https://adguard-dns.io/kb/general/dns-filtering-syntax/#badfilter-modifier)).
- `$ctag`:
  - A fixed set of 21 tags: 12 `device_*`, 6 `os_*`, 3 `user_*` ([KB Syntax › ctag](https://adguard-dns.io/kb/general/dns-filtering-syntax/#ctag-modifier)).
  - Custom tags: not supported ([#3086](https://github.com/AdguardTeam/AdGuardHome/issues/3086) open).
- Hosts-style rules:
  - The IP in the rule becomes the answer, and only the exact name matches, not subdomains. `0.0.0.0` or loopback addresses effectively block ([KB Syntax › basic examples](https://adguard-dns.io/kb/general/dns-filtering-syntax/#basic-examples); [› /etc/hosts syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/#etc-hosts-syntax)).
  - Domains-only lines match the exact name. Lines that are not valid domains are parsed as Adblock rules ([KB Syntax › domains-only](https://adguard-dns.io/kb/general/dns-filtering-syntax/#domains-only-syntax)).
- Rule tester: `GET /control/filtering/check_host` tests a hostname, with optional `client` and `qtype` (added in v0.107.58) ([openapi.yaml L765](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L765); [CHANGELOG L763](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L763)).

#### Blocked services

- Catalogue:
  - Generated from HostlistsRegistry `services.json` ([scripts/blocked-services/main.go L27](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/scripts/blocked-services/main.go#L27)).
  - 139 services at v0.107.79 and 142 on master, in 12 groups: ai, cdn, dating, gambling, gaming, hosting, messenger, privacy, shopping, social_network, software, streaming ([servicelist.go](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/servicelist.go); [servicelist.go at v0.107.79](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/internal/filtering/servicelist.go)).
  - Each service is a list of Adblock-style rules ([servicelist.go L20-L33](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/servicelist.go#L20-L33)).
- User-defined services: not supported ([#1692](https://github.com/AdguardTeam/AdGuardHome/issues/1692) open).
- Schedule:
  - A weekly schedule of one start–end window per weekday plus a time zone ([KB Configuration › filtering](https://adguard-dns.io/kb/adguard-home/configuration/#filtering)).
  - Available globally and per client (`blocked_services_schedule`) ([openapi.yaml Client L2831](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L2831)).
  - More than one window per day: not supported ([#6326](https://github.com/AdguardTeam/AdGuardHome/issues/6326) open).

#### Safe search, safe browsing, parental control

- Safe search:
  - Engines: Bing, DuckDuckGo, Ecosia, Google, Pixabay, Yandex, YouTube. Each can be toggled, globally or per client ([KB Configuration › filtering](https://adguard-dns.io/kb/adguard-home/configuration/#filtering); [› clients](https://adguard-dns.io/kb/adguard-home/configuration/#clients)).
  - Off by default ([config.go L377-L386](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L377-L386)).
  - Ecosia was added in v0.107.53 ([CHANGELOG L922](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L922)).
- How safe search works: built-in `$dnsrewrite` CNAME rules ([safesearch/rules](https://github.com/AdguardTeam/AdGuardHome/tree/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/safesearch/rules)). For example:
  - `www.google.*` → `forcesafesearch.google.com`
  - YouTube → `restrictmoderate.youtube.com`
  - Bing → `strict.bing.com`
  - DuckDuckGo → `safe.duckduckgo.com`
- Safe browsing and parental control:
  - Lookups go to a hard-coded upstream, `https://family.adguard-dns.com/dns-query`, as TXT queries under `sb.dns.adguard.com.` or `pc.dns.adguard.com.` ([home.go L455-L464](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/home.go#L455-L464)).
  - No configuration key to change this server was found ([home.go L489](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/home.go#L489)).
  - Both are off by default ([config.go L368-L369](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L368-L369)).
- Privacy model (k-anonymity style):
  - AdGuard Home hashes the hostname and each parent domain (stopping at the public suffix) with SHA-256 and sends only the first 2 bytes (4 hex characters) of each hash ([hashprefix.go L150-L175](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/hashprefix/hashprefix.go#L150-L175)).
  - The server answers with full hashes in TXT records, and the match is made locally ([hashprefix.go L22-L31](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/hashprefix/hashprefix.go#L22-L31); [hashprefix.go L150-L188](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/hashprefix/hashprefix.go#L150-L188)).
- Block responses and caching:
  - Safe browsing hits answer with `safebrowsing_block_host` (default `standard-block.dns.adguard.com`); parental hits with `parental_block_host` (default `family-block.dns.adguard.com`) ([config.go L257-L258](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L257-L258)).
  - Each has a 1 MiB cache. `cache_time` is in minutes, default 30 ([config.go L372-L375](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L372-L375); [home.go L481](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/home.go#L481)).
  - **Disagreements:**
    - The KB lists `cache_time` under both `dns` ("in seconds") and `filtering` ("in minutes"); the source reads it from `filtering`, in minutes ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [filtering.go L166](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go#L166)).
    - The FAQ calls the block-host keys `dns.parental_block_host` and `dns.safebrowsing_block_host`, but the source and the Configuration page put them under `filtering` ([KB FAQ › custom block page](https://adguard-dns.io/kb/adguard-home/faq/#customblock); [filtering.go L136-L140](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go#L136-L140)).

#### Blocking modes, response filtering, pause

- Blocking modes ([KB Configuration › filtering](https://adguard-dns.io/kb/adguard-home/configuration/#filtering)):
  - `default`: `0.0.0.0` / `::` for Adblock-style rules, and the rule's own IP for hosts-style rules.
  - `null_ip`
  - `nxdomain`
  - `refused`
  - `custom_ip`, using `blocking_ipv4` and `blocking_ipv6`.
- The TTL of blocked responses defaults to 10 s ([config.go L361](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L361)).
- Custom block page:
  - Only possible by pointing a custom IP, or the block hosts, at your own web server; HTTPS sites will show certificate warnings ([KB FAQ › custom block page](https://adguard-dns.io/kb/adguard-home/faq/#customblock)).
  - RFC 8914 Extended DNS Errors and the error-page draft are "not yet" implemented; AdGuard says it will add them once browsers support them ([KB FAQ › custom block page](https://adguard-dns.io/kb/adguard-home/faq/#customblock)).
- Response filtering (CNAME uncloaking):
  - The answer section is filtered too: CNAME targets, A/AAAA addresses and HTTPS hints are each checked against the rules. Hits are logged as "Blocked by CNAME or IP" ([KB FAQ › logs (CNAME question)](https://adguard-dns.io/kb/adguard-home/faq/#logs); [filter.go L111-L160](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/filter.go#L111-L160)).
  - Rules can match response IPs, e.g. `|10.*` ([#102 maintainer comment](https://github.com/AdguardTeam/AdGuardHome/issues/102#issuecomment-627335232)).
- DNS rebinding:
  - Not a resolver feature. It is offered as a vetted list, "HaGeZi's DNS Rebind Protection", added in v0.107.67 ([CHANGELOG L534](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L534); [#102](https://github.com/AdguardTeam/AdGuardHome/issues/102#issuecomment-3347540839)).
- Protection on/off:
  - `protection_enabled` is the global switch. It does not disable `$dnsrewrite` rules, DNS rewrites or rewrites from the OS hosts file ([KB Configuration › filtering](https://adguard-dns.io/kb/adguard-home/configuration/#filtering)).
- Pausing protection:
  - `POST /control/protection` takes a pause `duration` in ms; the end time is stored as `protection_disabled_until` ([openapi.yaml L101-L114](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L101-L114); [openapi.yaml L2732-L2743](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L2732-L2743)).
  - UI presets: 30 s, 1 min, 10 min, 1 h, "tomorrow" ([constants.ts L512-L518](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/src/helpers/constants.ts#L512-L518)).
  - A per-client pause is not in the client schema ([openapi.yaml Client L2831](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L2831)).
- Timed or scheduled lists: not supported ([#1203](https://github.com/AdguardTeam/AdGuardHome/issues/1203) open, v0.110.0 milestone). Temporary unblock: not supported ([#2823](https://github.com/AdguardTeam/AdGuardHome/issues/2823) open).

### 3. Clients

- Runtime clients:
  - Friendly names come from hosts files, rDNS, the ARP table, WHOIS (public IPs) and DHCP leases ([KB Clients › friendly names](https://adguard-dns.io/kb/adguard-home/clients/#friendly-names)).
  - Each source is a switch under `clients.runtime_sources`, all on by default ([KB Configuration › clients](https://adguard-dns.io/kb/adguard-home/configuration/#clients); [config.go L406-L414](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L406-L414)).
- Persistent clients:
  - Identified by IP, CIDR, MAC (only when AdGuard Home is the network's DHCP server) or ClientID ([KB Clients › identifying clients](https://adguard-dns.io/kb/adguard-home/clients/#identifying-clients)).
  - MAC matching without the built-in DHCP server: not supported ([#961](https://github.com/AdguardTeam/AdGuardHome/issues/961) open).
- ClientID ([KB Clients › ClientID](https://adguard-dns.io/kb/adguard-home/clients/#client-id)):
  - DoH: in the URL path (`/dns-query/<id>`) or as an SNI subdomain. DoT and DoQ: SNI subdomain only.
  - SNI subdomains need a wildcard certificate.
  - When both are present, the URL ClientID wins.
  - DoH routes are configurable under `http.doh.routes` ([KB Configuration › http](https://adguard-dns.io/kb/adguard-home/configuration/#http)).
- Per-client settings ([KB Configuration › clients](https://adguard-dns.io/kb/adguard-home/configuration/#clients); [openapi.yaml Client L2831](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L2831)):
  - Use global settings or override them.
  - Filtering on/off, parental control, safe browsing, safe search per engine.
  - Blocked services and their schedule.
  - Own upstream list, plus its own cache (on/off and size).
  - Tags.
  - Exclude from the query log; exclude from statistics.
- Not available per client:
  - Assigning blocklists to a client: not supported ([#8029](https://github.com/AdguardTeam/AdGuardHome/issues/8029) open). Per-client rules are only possible in custom rules via `$client` or `$ctag` ([KB Clients › per-client blocking](https://adguard-dns.io/kb/adguard-home/clients/#per-client-blocking)).
  - Client groups: not supported ([#2527](https://github.com/AdguardTeam/AdGuardHome/issues/2527) open).
  - Per-client DNS rewrites, other than `$dnsrewrite` + `$client`: not supported ([#4425](https://github.com/AdguardTeam/AdGuardHome/issues/4425) open).
- Access control ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [KB Running securely › access settings](https://adguard-dns.io/kb/adguard-home/running-securely/#access-settings)):
  - `allowed_clients` (allowlist mode) takes IPs, CIDRs or ClientIDs.
  - `disallowed_clients` are dropped, and the list is ignored when `allowed_clients` is non-empty.
  - `blocked_hosts` ("disallowed domains") are not processed at all and are left out of the query log and stats.
- `blocked_hosts`:
  - Default: `version.bind`, `id.server`, `hostname.bind` ([dnsforward.go L54](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/dnsforward.go#L54)).
  - Accepts `$dnstype` rules ([CHANGELOG L2159](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L2159)).
- Rate limiting ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L309-L318](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L309-L318)):
  - `ratelimit` default: 20 queries/s per client subnet (/24 for IPv4, /56 for IPv6). Excess queries are "silently dropped".
  - Exemptions via `ratelimit_whitelist`.
  - `refuse_any` default: true.
- Concurrency cap: `max_goroutines`, default 300 ([config.go L303-L307](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L303-L307)).
- Ignored request: IP/CIDR/domain lists in access settings ([#1032](https://github.com/AdguardTeam/AdGuardHome/issues/1032) open, v1.0.0 milestone).

### 4. DNS resolution

- Forwarding only:
  - AdGuard Home is "basically a DNS proxy that sends your DNS queries to upstream servers" ([KB Configuration › upstreams](https://adguard-dns.io/kb/adguard-home/configuration/#upstreams)).
  - Recursive resolution is not supported; it is [#790](https://github.com/AdguardTeam/AdGuardHome/issues/790), open in the v1.0.0 milestone.
  - Maintainers dropped libunbound because of CGO and cross-compiling, and said in 2021 "we shouldn't implement a recursor ourselves" ([#790 comments](https://github.com/AdguardTeam/AdGuardHome/issues/790#issuecomment-825494370)).
- Upstream protocols ([KB Configuration › upstreams](https://adguard-dns.io/kb/adguard-home/configuration/#upstreams)):
  - Plain UDP and TCP.
  - DoT (`tls://`), DoH (`https://`), DoH forced over HTTP/3 (`h3://`), DoQ (`quic://`).
  - `sdns://` stamps for DNSCrypt or DoH.
- `use_http3_upstreams` upgrades DoH upstreams to HTTP/3 where the server supports it ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)).
- DNSCrypt Anonymized DNS: not supported ([#1226](https://github.com/AdguardTeam/AdGuardHome/issues/1226) open).
- Per-domain upstreams (conditional forwarding) ([KB Configuration › upstreams for domains](https://adguard-dns.io/kb/adguard-home/configuration/#upstreams-for-domains)):
  - dnsmasq-style syntax: `[/d1/d2/]upstream …`.
  - `[//]` means unqualified (dotless) names; `[/*.d/]` means subdomains only; `#` means "use the default upstreams".
  - The most specific domain wins.
  - `DS` queries are routed to the parent zone's upstream (RFC 4035 §2.4).
- Upstreams can be loaded from a file (`upstream_dns_file`). Internationalised domain names must be written in Punycode ([KB Configuration › upstreams from file](https://adguard-dns.io/kb/adguard-home/configuration/#upstreams-from-file); [#2915](https://github.com/AdguardTeam/AdGuardHome/issues/2915) open, v1.0.0 milestone).
- Private reverse DNS ([KB Configuration › rdns private](https://adguard-dns.io/kb/adguard-home/configuration/#rdns-private)):
  - PTR, SOA and NS queries for locally served ranges (RFC 6303 by default, or `private_networks`) go only to `local_ptr_upstreams`, which default to the OS resolvers.
  - With `use_private_ptr_resolvers` off, such queries get `NXDOMAIN`.
  - Client names are looked up by rDNS as well ([KB Configuration › rdns clients](https://adguard-dns.io/kb/adguard-home/configuration/#rdns-clients)).
- Upstream modes ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L291](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L291); [config.go L300](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L300)):
  - `load_balance` (default): weighted random choice by failures and average latency.
  - `parallel`
  - `fastest_addr`: probes the returned addresses and answers with the fastest; `fastest_timeout` default 1 s.
- Bootstrap, fallback, timeouts and testing:
  - `bootstrap_dns` (with `bootstrap_prefer_ipv6`) and `fallback_dns` (used "when upstream DNS servers are not responding") ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)).
  - Upstream timeout default 10 s ([dnsforward.go L41](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/dnsforward.go#L41)); settable in the UI since v0.107.57 ([CHANGELOG L798](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L798)).
  - Upstream test API: `POST /control/test_upstream_dns` ([openapi.yaml L124](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L124)).
- Coalescing identical in-flight queries: `pending_requests.enabled` (default true) for "cache poisoning attacks protection" ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L288-L290](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L288-L290)).
- Cache ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L298-L314](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L298-L314)):
  - On by default; size in bytes, default 4 MiB.
  - `cache_ttl_min` and `cache_ttl_max` override upstream TTLs.
  - Optimistic cache (serve stale while refreshing) has `cache_optimistic_answer_ttl` (default 30 s) and `cache_optimistic_max_age` (default 12 h).
  - **Disagreement:** the KB says optimistic answers get a 10-second TTL; the source default is 30 s.
- Cache management:
  - Per-client caches ([KB Configuration › clients](https://adguard-dns.io/kb/adguard-home/configuration/#clients)).
  - Whole-cache flush via `POST /control/cache_clear` ([openapi.yaml L115](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L115)).
  - Not supported: flushing one domain ([#5273](https://github.com/AdguardTeam/AdGuardHome/issues/5273)), cache prefetch ([#1259](https://github.com/AdguardTeam/AdGuardHome/issues/1259), v1.0.0 milestone), no-cache rules per domain ([#4197](https://github.com/AdguardTeam/AdGuardHome/issues/4197)). All are open.
- DNSSEC: **pass-through only, no local validation.**
  - `enable_dnssec` (default true since v0.107.75) "defines whether the proxy should set the DO flag in the upstream requests" ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [CHANGELOG L226](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L226)).
  - Since v0.107.0, "The DNSSEC check now simply checks against the AD flag in the response" ([CHANGELOG L3143](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L3143)).
  - The upstream's AD bit is copied into the query log ([process.go L497](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/process.go#L497); [entry.go L44](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/querylog/entry.go#L44)).
  - "Full DNSSEC support" ([#1579](https://github.com/AdguardTeam/AdGuardHome/issues/1579)) is open. The request for an enforceable validation setting was closed as its duplicate ([#5806](https://github.com/AdguardTeam/AdGuardHome/issues/5806)).
- EDNS Client Subnet:
  - `edns_client_subnet.enabled` adds ECS to upstream queries, using the client's network or a fixed `custom_ip` ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)).
  - Not supported: using an incoming ECS as the client identity ([#1727](https://github.com/AdguardTeam/AdGuardHome/issues/1727)), retrying without ECS on REFUSED ([#3652](https://github.com/AdguardTeam/AdGuardHome/issues/3652)). Both are open.
- IPv6 ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)):
  - `aaaa_disabled` returns empty AAAA answers and strips IPv6 hints from HTTPS records.
  - DNS64: `use_dns64` and `dns64_prefixes` (default `64:ff9b::/96`).
- Other DNS options ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L316](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L316)):
  - DDR (`handle_ddr`, default true).
  - `bogus_nxdomain` (IPs and CIDRs).
  - ipset integration (`ipset` / `ipset_file`, Linux only, like dnsmasq `--ipset`).
  - Not supported: nftables sets ([#5136](https://github.com/AdguardTeam/AdGuardHome/issues/5136)) and reloading `ipset_file` without a restart ([#5676](https://github.com/AdguardTeam/AdGuardHome/issues/5676)). Both are open.
- DNS rewrites (local records):
  - The UI list maps a domain or wildcard to an IP, a CNAME, or the special values `A` / `AAAA` (keep the upstream records). Each entry has `enabled` ([KB Configuration › filtering](https://adguard-dns.io/kb/adguard-home/configuration/#filtering)).
  - A global rewrites toggle has had its own API since v0.107.68 ([CHANGELOG L487](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L487); [openapi.yaml L1189](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L1189)).
  - Richer records use `$dnsrewrite` rules (section 2) ([KB Syntax › dnsrewrite](https://adguard-dns.io/kb/general/dns-filtering-syntax/#dnsrewrite-modifier)).
  - A separate TTL for rewrites: not supported ([#1518](https://github.com/AdguardTeam/AdGuardHome/issues/1518) open).
- `/etc/hosts`:
  - `dns.hostsfile_enabled` (default true) answers queries from the OS hosts file ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [config.go L317](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L317)).
  - The same file names clients ([KB Clients › friendly names](https://adguard-dns.io/kb/adguard-home/clients/#friendly-names)).
  - The `--no-etc-hosts` flag is deprecated ([KB Configuration › command-line](https://adguard-dns.io/kb/adguard-home/configuration/#command-line)).

### 5. Encrypted DNS serving

- Protocols:
  - Serves DoH, DoT and DoQ "out-of-the-box", and DNSCrypt as both client and server ([KB Encryption](https://adguard-dns.io/kb/adguard-home/encryption/)).
  - Ports: `port_https` (443, shared by the web UI and DoH), `port_dns_over_tls` (853), `port_dns_over_quic` (853/udp), `port_dnscrypt` ([KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).
- `serve_http3` turns on HTTP/3 for DoH and for the web UI ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)).
- DNSCrypt server:
  - Configured in the YAML file only, not in the UI ([KB Encryption › configure DNSCrypt](https://adguard-dns.io/kb/adguard-home/encryption/#configure-dnscrypt)).
  - Needs a key/config file generated with the separate `dnscrypt` tool; the stamp is built by hand at dnscrypt.info ([KB Encryption › configure DNSCrypt](https://adguard-dns.io/kb/adguard-home/encryption/#configure-dnscrypt)).
- Plain DNS can be turned off (`serve_plain_dns: false`), but only while at least one encrypted protocol is enabled ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [KB Running securely › disabling plain DNS](https://adguard-dns.io/kb/adguard-home/running-securely/#disabling-plain-dns)).
- Certificates:
  - PEM, either pasted inline or as file paths ([KB Encryption › configure](https://adguard-dns.io/kb/adguard-home/encryption/#configure); [KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).
  - No built-in ACME: the KB walks through certbot or lego with DNS challenges ([KB Encryption › certificate](https://adguard-dns.io/kb/adguard-home/encryption/#certificate)); ACME support is [#1603](https://github.com/AdguardTeam/AdGuardHome/issues/1603), open.
  - Certificates given by path reload automatically on change (v0.107.72) or on `SIGHUP` / `-s reload` ([KB Encryption › configure](https://adguard-dns.io/kb/adguard-home/encryption/#configure); [CHANGELOG L329](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L329)).
- TLS settings:
  - TLS 1.2 minimum ([aghtls/defaultmanager.go L172](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/aghtls/defaultmanager.go#L172)).
  - `override_tls_ciphers` replaces the cipher suites ([KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).
  - `server_name` drives SNI ClientIDs and DDR ([KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).
  - `force_https` adds an HTTP→HTTPS redirect and HSTS ([KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).
  - `strict_sni_check` was deprecated in v0.107.79 ([CHANGELOG L94](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L94)).
- Behind a reverse proxy:
  - `http.doh.insecure_enabled` allows DoH over plain HTTP. It replaced `tls.allow_unencrypted_doh` in config schema 34 (v0.107.74) ([KB Configuration › http](https://adguard-dns.io/kb/adguard-home/configuration/#http); [CHANGELOG L262-L288](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L262-L288)).
  - **Disagreement:** the FAQ still says to set `allow_unencrypted_doh: true` ([KB FAQ › disable DoH encryption](https://adguard-dns.io/kb/adguard-home/faq/#disable-doh-encryption-on-adguard-home)).
- `trusted_proxies`:
  - Default `127.0.0.0/8` and `::1` ([config.go L293-L297](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L293-L297); [KB Encryption › reverse proxy](https://adguard-dns.io/kb/adguard-home/encryption/#reverse-proxy)).
  - Real-IP headers, in the order checked: `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `X-Forwarded-For` ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [KB Encryption › reverse proxy](https://adguard-dns.io/kb/adguard-home/encryption/#reverse-proxy); [config.go L293-L297](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L293-L297)).
- Not supported, all with open issues:
  - PROXY protocol ([#2798](https://github.com/AdguardTeam/AdGuardHome/issues/2798), 95 👍, v1.0.0 milestone).
  - Oblivious DoH ([#2406](https://github.com/AdguardTeam/AdGuardHome/issues/2406), v0.109.0 milestone).
  - Separate ports for DoH and the web UI ([#741](https://github.com/AdguardTeam/AdGuardHome/issues/741)).
- Apple configuration profiles:
  - The Setup Guide generates `.mobileconfig` profiles for DoH and DoT ([KB Encryption › iOS](https://adguard-dns.io/kb/adguard-home/encryption/#ios); [openapi.yaml L1382](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L1382)).
  - Signing them: not supported ([#3110](https://github.com/AdguardTeam/AdGuardHome/issues/3110) open).
- H2C (HTTP/2 cleartext) upgrade over HTTP/1.1 was removed in v0.107.78, after a critical auth bypass (section 10) ([CHANGELOG L128](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L128)).

### 6. DHCP server

- DHCPv4 and DHCPv6 server. Not supported on Windows, and the host needs a static IP ([KB DHCP › prerequisites](https://adguard-dns.io/kb/adguard-home/dhcp/#prerequisites)). Windows support is [#616](https://github.com/AdguardTeam/AdGuardHome/issues/616), open in the v1.0.0 milestone.
- Settings ([KB Configuration › dhcp](https://adguard-dns.io/kb/adguard-home/configuration/#dhcp)):
  - Interface, gateway, subnet mask, address range.
  - Lease duration, default 24 h.
  - ICMP-based IP conflict detection (`icmp_timeout_msec`).
- By default, AdGuard Home hands out itself as the clients' DNS server ([KB DHCP › configuration](https://adguard-dns.io/kb/adguard-home/dhcp/#configuration)).
- Custom DHCPv4 options:
  - Config file only. Types: `bool`, `del`, `dur`, `hex`, `ip`, `ips`, `text`, `u8`, `u16` ([KB DHCP › DHCPv4 options](https://adguard-dns.io/kb/adguard-home/dhcp/#dhcpv4-options)).
  - Values are not validated per option ([KB DHCP › DHCPv4 options](https://adguard-dns.io/kb/adguard-home/dhcp/#dhcpv4-options)).
- DHCPv6 has a range start plus Router Advertisements, either SLAAC-only (`ra_slaac_only`, which stops the DHCPv6 server) or SLAAC-allowed (`ra_allow_slaac`) ([KB DHCP › DHCPv6 options](https://adguard-dns.io/kb/adguard-home/dhcp/#dhcpv6-options)).
- API for static leases (add, update, remove), resetting config and leases, and detecting other DHCP servers on the link (`/dhcp/find_active_dhcp`) ([openapi.yaml L486-L651](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L486-L651)).
- Automatic hosts:
  - DHCP clients become resolvable as `<hostname>.lan`, but only to clients in locally served networks ([KB DHCP › auto hosts](https://adguard-dns.io/kb/adguard-home/dhcp/#auto-hosts); [KB Configuration › dhcp](https://adguard-dns.io/kb/adguard-home/configuration/#dhcp)).
  - **Disagreement:** the DHCP page calls the TLD key `dns.local_domain_name`, but the source and the Configuration page use `dhcp.local_domain_name` ([dhcpd/config.go L45](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dhcpd/config.go#L45); [config.go L396-L397](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L396-L397)).
- Leases are stored in `data/leases.json`; "The file format is not stable" ([KB DHCP › stored leases](https://adguard-dns.io/kb/adguard-home/dhcp/#stored-leases)).
- Running DHCP without root needs `CAP_NET_RAW` in addition to `CAP_NET_BIND_SERVICE` ([KB Getting started › running without superuser](https://adguard-dns.io/kb/adguard-home/getting-started/#running-without-superuser)).
- Not supported, all with open issues:
  - Serving more than one interface ([#3539](https://github.com/AdguardTeam/AdGuardHome/issues/3539), 71 👍).
  - Custom DHCPv6 prefix length ([#5005](https://github.com/AdguardTeam/AdGuardHome/issues/5005)).
  - Using `home.arpa` (RFC 8375) as the local domain ([#4981](https://github.com/AdguardTeam/AdGuardHome/issues/4981)).

### 7. Query log and statistics

- Query log defaults ([config.go L327-L335](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L327-L335)):
  - On, written to a file, 90-day retention, 1000 entries buffered in memory.
- Retention choices:
  - UI: 6 h, 1, 7, 30 or 90 days, or a custom value ([constants.ts L178-L186](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/src/helpers/constants.ts#L178-L186)).
  - Config file: 1 h to 8760 h. `file_enabled: false` keeps the log in memory only. `dir_path` moves it ([KB Configuration › querylog](https://adguard-dns.io/kb/adguard-home/configuration/#querylog)).
- Storage: a JSON file, `querylog.json`, rotated to `querylog.json.1` ([qlog.go L21-L23](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/querylog/qlog.go#L21-L23); [querylogfile.go L103-L105](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/querylog/querylogfile.go#L103-L105)).
- Recorded per query ([entry.go L16-L44](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/querylog/entry.go#L16-L44); [openapi.yaml QueryLogItem L2286](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L2286)):
  - Time; question name, type and class.
  - Client IP, ClientID, protocol, ECS.
  - Upstream used; answer and original (pre-filter) answer.
  - Filtering result and matched rules; blocked service name.
  - Elapsed time; cached flag; AD flag.
  - WHOIS and client info are attached when served through the API.
- Search API (`GET /control/querylog`) ([openapi.yaml L193-L260](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L193-L260)):
  - `search` (domain or client IP).
  - `reason` (multi-valued filter, added v0.107.77; replaces the deprecated `response_status`).
  - Paging via `older_than` / `offset` / `limit`.
  - Filtering by date: not supported ([#481](https://github.com/AdguardTeam/AdGuardHome/issues/481) open).
- Exclusions ([KB Configuration › querylog](https://adguard-dns.io/kb/adguard-home/configuration/#querylog); [› clients](https://adguard-dns.io/kb/adguard-home/configuration/#clients)):
  - An `ignored` host list in Adblock syntax, with `ignored_enabled`.
  - Per-client `ignore_querylog`.
- Anonymisation ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [querylog/http.go L152-L164](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/querylog/http.go#L152-L164)):
  - `anonymize_client_ip` applies to both logs and stats.
  - IPv4: the last 2 bytes are zeroed, leaving a /16. IPv6: the last 10 bytes are zeroed, leaving a /48.
- Export from the UI or API: not supported. Both requests are open: [#3389](https://github.com/AdguardTeam/AdGuardHome/issues/3389) (v0.109.0) and [#1176](https://github.com/AdguardTeam/AdGuardHome/issues/1176) (v1.0.0). A size cap for the log file is also missing ([#4284](https://github.com/AdguardTeam/AdGuardHome/issues/4284) open).
- Statistics retention:
  - Default 1 day ([config.go L336-L342](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L336-L342)).
  - UI choices: 1, 7, 30 or 90 days, or custom ([constants.ts L178](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/client/src/helpers/constants.ts#L178)).
  - Config file: 1 h to 8760 h, plus an ignore list and per-client `ignore_statistics` ([KB Configuration › statistics](https://adguard-dns.io/kb/adguard-home/configuration/#statistics)).
- Statistics contents ([openapi.yaml Stats L1917](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L1917); [› /stats L336-L361](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L336-L361)):
  - Totals: queries; blocked by filters; safe browsing, safe search and parental hits.
  - Average processing time.
  - Top queried domains, top blocked domains, top clients.
  - Top upstreams by responses and by average time.
  - Time series.
  - A `recent` lookback parameter.
- Statistics storage: bbolt file `stats.db`, which needs `mmap` ([home/dns.go L60](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/dns.go#L60); [KB Getting started › limitations](https://adguard-dns.io/kb/adguard-home/getting-started/#limitations)).
- Not supported, all with open issues: per-blocklist statistics ([#4524](https://github.com/AdguardTeam/AdGuardHome/issues/4524)), live dashboard updates ([#1739](https://github.com/AdguardTeam/AdGuardHome/issues/1739)), breakdown by protocol ([#1731](https://github.com/AdguardTeam/AdGuardHome/issues/1731)).

### 8. Interfaces

- First start:
  - The setup wizard listens on `0.0.0.0:3000`, where you pick the interfaces and create the admin user ([KB Getting started › first start](https://adguard-dns.io/kb/adguard-home/getting-started/#first-time)).
  - The default `http.address` is also `0.0.0.0:3000` ([config.go L281](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L281)).
- Web UI:
  - Pages: Dashboard; Filters (DNS blocklists, DNS allowlists, DNS rewrites, blocked services, custom filtering rules); Query Log; Settings (General, DNS, Encryption, Client, DHCP); Setup Guide ([KB FAQ › doesn't block](https://adguard-dns.io/kb/adguard-home/faq/#doesntblock); [KB Encryption › iOS](https://adguard-dns.io/kb/adguard-home/encryption/#ios)).
  - Themes auto, dark and light ([KB Configuration › theme](https://adguard-dns.io/kb/adguard-home/configuration/#theme)); translations are done on Crowdin ([README L354-L359](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L354-L359)).
  - The UI only lets you pick one DNS listen interface; more can be added in YAML ([KB Running securely › choosing server addresses](https://adguard-dns.io/kb/adguard-home/running-securely/#choosing-server-addresses)).
  - Some settings exist in YAML only: DNSCrypt, DHCP options, block-page hosts ([KB Encryption › configure DNSCrypt](https://adguard-dns.io/kb/adguard-home/encryption/#configure-dnscrypt); [KB FAQ › custom block page](https://adguard-dns.io/kb/adguard-home/faq/#customblock)).
  - Changing the admin password in the UI: not supported ([#1321](https://github.com/AdguardTeam/AdGuardHome/issues/1321) open); the KB documents resetting it with `htpasswd` ([KB Configuration › password reset](https://adguard-dns.io/kb/adguard-home/configuration/#password-reset)).
- REST API:
  - Served under `/control/*`, described in `openapi/openapi.yaml` (`info.version: '0.107'`, HTTP Basic auth). "Our admin web interface is built on top of this REST-ish API" ([openapi.yaml L1-L12](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L1-L12); [openapi.yaml L3386-L3389](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/openapi.yaml#L3386-L3389)).
  - Breaking changes are logged in `openapi/CHANGELOG.md` ([openapi/README.md L9-L21](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/README.md?plain=1#L9-L21); [openapi/CHANGELOG.md](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/CHANGELOG.md)).
  - The spec is maintained by hand ("We do that manually") ([#573 comment](https://github.com/AdguardTeam/AdGuardHome/issues/573#issuecomment-627008133)).
- Next API (draft):
  - `/api/v1` in `openapi/next.yaml`: "API IS AT THE DRAFT STAGE! THINGS WILL BREAK!", "not covered by any stability guarantees" ([next.yaml L1-L20](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/next.yaml#L1-L20)).
  - The old `/control/` API "will mostly be removed" once it matures. The draft includes `/health-check` ([next.yaml L1-L20](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/next.yaml#L1-L20); [next.yaml L86-L89](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/next.yaml#L86-L89); [next.yaml L128](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/next.yaml#L128)).
- CLI flags ([KB Configuration › command-line](https://adguard-dns.io/kb/adguard-home/configuration/#command-line); matches [options.go](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/options.go)):
  - `-c` config, `-w` work dir, `--web-addr`.
  - `-s` service control: `status`, `install`, `uninstall`, `start`, `stop`, `restart`, `reload`.
  - `-l` log file, `--pidfile`, `--check-config`, `--no-check-update`, `--update`.
  - `--local-frontend`, `-v`, `--glinet`, `--no-permcheck`, `--version`.
  - Deprecated: `-h`/`--host`, `-p`/`--port`, `--no-mem-optimization`, `--no-etc-hosts`.
- Config file:
  - YAML, `AdGuardHome.yaml`, at `schema_version` 34 (since v0.107.74). Older files are migrated automatically on start ([configmigrate.go L4-L5](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/configmigrate/configmigrate.go#L4-L5); [CHANGELOG L262](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L262)).
  - Edit only while stopped: "the running program will overwrite them" ([KB Configuration › configuration file](https://adguard-dns.io/kb/adguard-home/configuration/#configuration-file)).
  - Durations accept a `d` unit since v0.107.76 ([CHANGELOG L196](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L196)).
- Other interfaces:
  - Environment variable `ADGUARD_HOME_DEFAULT_WEB_PORT` sets the port suggested by the wizard ([KB Environment variables](https://adguard-dns.io/kb/adguard-home/environment/#ADGUARD_HOME_DEFAULT_WEB_PORT)).
  - Opt-in pprof on port 6060 ([KB Configuration › pprof](https://adguard-dns.io/kb/adguard-home/configuration/#pprof)).
  - Logs go to a file, syslog or the Windows event log, with rotation and gzip ([KB Configuration › log](https://adguard-dns.io/kb/adguard-home/configuration/#log)).
  - Outbound `http_proxy` (http, https, socks5) ([KB Configuration › http_proxy](https://adguard-dns.io/kb/adguard-home/configuration/#http_proxy)).
- Home Assistant:
  - The integration ships inside Home Assistant (code owner @frenck, local polling). It offers stats sensors, protection and filter switches, and filter-list actions ([Home Assistant: AdGuard Home](https://www.home-assistant.io/integrations/adguard/)).
  - The README links it and the PyPI client it uses ([README L125-L131](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L125-L131)), and lists the Python library and the HA add-on as "not affiliated" ([README L367-L375](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L367-L375)).
- Prometheus: **not supported**. The source has no metrics endpoint, and "Metrics endpoint for Prometheus" has been open since 2019 with 55 👍 ([#516](https://github.com/AdguardTeam/AdGuardHome/issues/516)).
- Other third-party tools listed as "not affiliated": AdGuardian-Term, a Zabbix template, a Node.js library, a browser extension, the iOS app "AdGuard Home Remote" ([README L367-L397](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L367-L397)).
- Not supported, both with open issues: liveness and readiness probes in the stable API ([#1979](https://github.com/AdguardTeam/AdGuardHome/issues/1979)), and an option to disable configuration through the web UI ([#1964](https://github.com/AdguardTeam/AdGuardHome/issues/1964)).

### 9. High availability, clustering, config sync

- **Nothing is built in.**
  - The KB has no HA, clustering, replication, floating-IP or sync feature ([KB AdGuard Home section](https://adguard-dns.io/kb/adguard-home/overview/)).
  - "Run 2 Instances Of AdGuard Home For Redundancy" is the most-upvoted open issue (154 👍), in the v0.108.0 milestone ([#573](https://github.com/AdguardTeam/AdGuardHome/issues/573); [open issues by 👍](https://github.com/AdguardTeam/AdGuardHome/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc)).
- Official statements in #573:
  - 2019: list both servers in the router's DHCP settings ([comment](https://github.com/AdguardTeam/AdGuardHome/issues/573#issuecomment-460157593)).
  - 2019: syncing by `rsync` of the config needs a stop and start ([comment](https://github.com/AdguardTeam/AdGuardHome/issues/573#issuecomment-518681940)).
  - 2021: the goal is to copy `AdGuardHome.yaml` and `data/`, then send `SIGHUP`. A full config reload is "basically impossible to do in the current architecture, but is an explicit goal of the v0.108.0 release". BGP or shared-IP setups are "not in the scope of the project right now" ([comment](https://github.com/AdguardTeam/AdGuardHome/issues/573#issuecomment-994817769)).
- Reload today:
  - `-s reload` only refreshes runtime clients from the ARP table and re-reads the TLS certificate ([KB Configuration › command-line](https://adguard-dns.io/kb/adguard-home/configuration/#command-line)).
  - Other config file changes need a stop and start ([KB Configuration › configuration file](https://adguard-dns.io/kb/adguard-home/configuration/#configuration-file)).
- `adguardhome-sync` (by @bakito) is third-party. The README lists it under projects that "are not affiliated with AdGuard" ([README L367-L379](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L367-L379)).
- Settings import and export: not supported ([#1147](https://github.com/AdguardTeam/AdGuardHome/issues/1147) open, 61 👍).
- State lives in local files only: YAML config, bbolt `stats.db` and `sessions.db`, JSON query log, JSON leases. Nothing is replicated or shared ([home/dns.go L60](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/dns.go#L60); [auth.go L20](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/auth.go#L20); [KB DHCP › stored leases](https://adguard-dns.io/kb/adguard-home/dhcp/#stored-leases)).

### 10. Security

#### Privileges and sandboxing

- Running without root ([KB Getting started › running without superuser](https://adguard-dns.io/kb/adguard-home/getting-started/#running-without-superuser)):
  - Linux: grant `CAP_NET_BIND_SERVICE` with `setcap`, plus `CAP_NET_RAW` for DHCP.
  - Any platform: use a DNS port above 1024.
  - The README comparison table claims "Running without root privileges" as a feature ([README L173](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L173)).
- Privilege drop: `os.user` and `os.group` switch to that user and group after startup, via `setgid` / `setuid` ([KB Configuration › os](https://adguard-dns.io/kb/adguard-home/configuration/#os); [aghos/user_unix.go L12-L48](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/aghos/user_unix.go#L12-L48)).
- Docker image:
  - The binary is owned by `nobody`, with `cap_net_bind_service=+eip` set ([docker/build.Dockerfile L33-L39](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/docker/build.Dockerfile#L33-L39)).
  - The Dockerfile has no `USER` instruction, so the process runs as the image default (root) unless overridden ([docker/build.Dockerfile L24-L39](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/docker/build.Dockerfile#L24-L39)).
- Snap uses `strict` confinement ([snap/snap.tmpl.yaml L16](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/snap/snap.tmpl.yaml#L16)).
- Sandboxing: **not documented, and not found in the source.** A search of `internal/` at `8dedd32` for seccomp, landlock, pledge, unveil, capsicum and `PR_SET_*` matched nothing. No systemd hardening is documented ([internal/ tree](https://github.com/AdguardTeam/AdGuardHome/tree/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal); [KB Running securely](https://adguard-dns.io/kb/adguard-home/running-securely/)).
- File permissions:
  - Since v0.107.53 (fix for CVE-2024-36586), AdGuard Home tightens permissions on its own files: directories `0700`, files `0600`. `--no-permcheck` skips this ([CHANGELOG L912-L914](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L912-L914); [aghos/os.go L27-L29](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/aghos/os.go#L27-L29)).
  - The KB asks for a root-owned, non-writable install directory, to prevent binary planting ([KB Running securely › OS service concerns](https://adguard-dns.io/kb/adguard-home/running-securely/#os-service-concerns)).

#### Web UI authentication

- Users:
  - A `users` list with bcrypt password hashes. An empty list **disables authentication** ([KB Configuration › users](https://adguard-dns.io/kb/adguard-home/configuration/#users); [auth.go L190](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/auth.go#L190)).
  - No roles: a user is just a login, a password and an ID ([aghuser/user.go L34-L44](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/aghuser/user.go#L34-L44)).
- Not supported, all with open issues: user accounts with permissions ([#997](https://github.com/AdguardTeam/AdGuardHome/issues/997)), TOTP 2FA ([#1667](https://github.com/AdguardTeam/AdGuardHome/issues/1667)), auth proxy ([#1737](https://github.com/AdguardTeam/AdGuardHome/issues/1737)).
- Brute-force protection:
  - `auth_attempts` (default 5) and `block_auth_min` (default 15 min) ([KB Configuration › auth_attempts](https://adguard-dns.io/kb/adguard-home/configuration/#auth_attempts); [config.go L265-L266](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L265-L266)).
  - Failed logins are counted per direct remote IP; proxy headers are deliberately not used for this ([authhttp.go L108-L160](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/authhttp.go#L108-L160)).
- Sessions:
  - Cookie `agh_session`, `HttpOnly`, `SameSite=Lax`, stored in `sessions.db`, with a 30-day session TTL ([authhttp.go L235-L242](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/authhttp.go#L235-L242); [config.go L282](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L282)).
  - `SameSite=Lax` was the fix for CSRF CVE-2022-32175 in v0.107.14 ([CHANGELOG L2557-L2575](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L2557-L2575)).
- API clients can also use HTTP Basic auth ([openapi/README.md L13-L21](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/openapi/README.md?plain=1#L13-L21)).
- TLS for the UI: it uses the same certificate and HTTPS port as DoH, with optional `force_https` + HSTS and HTTP/3 ([KB Configuration › tls](https://adguard-dns.io/kb/adguard-home/configuration/#tls)).

#### Release integrity and disclosure

- Releases and reporting:
  - Binaries are GPG-signed with key `28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6`, and builds are described as reproducible ([KB Running securely › verify releases](https://adguard-dns.io/kb/adguard-home/running-securely/#verify-releases); [› reproducing builds](https://adguard-dns.io/kb/adguard-home/running-securely/#reproducing-builds)).
  - Vulnerabilities go by email to `security@adguard.com`; follow up if there is no reply within 7 days ([SECURITY.md L1-L13](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/SECURITY.md?plain=1#L1-L13)).
- Published repo advisories (3 returned by the GitHub advisories API on 2026-10-09):
  - GHSA-5fg6-wrq4-w5gh / CVE-2026-32136, **critical**: h2c-upgrade authentication bypass, published 2026-03-11, fixed in v0.107.73 ([advisory](https://github.com/AdguardTeam/AdGuardHome/security/advisories/GHSA-5fg6-wrq4-w5gh); [CHANGELOG L313](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L313)).
  - GHSA-xgx4-4h9w-53pv / CVE-2026-47703, low: DoQ-to-UDP query-ID issue ([advisory](https://github.com/AdguardTeam/AdGuardHome/security/advisories/GHSA-xgx4-4h9w-53pv)).
  - GHSA-73vv-3434-p64c, low: DoQ DoS ([advisory](https://github.com/AdguardTeam/AdGuardHome/security/advisories/GHSA-73vv-3434-p64c)).
- 2026 security fixes in the CHANGELOG ([CHANGELOG L76-L192](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L76-L192)):
  - GL.iNet-mode path traversal CVE-2026-41448 (v0.107.77).
  - JIGGLE resistance; stricter checks on DoH and DNSCrypt upstream responses; QUIC unbounded reads; a size cap on rule lists (v0.107.78).
  - DoQ resource exhaustion (v0.107.79).
  - Several cited GHSA IDs (e.g. GHSA-w6v6-f44j-3rj2, GHSA-p5f5-3p5g-rfjw) were not returned as published advisories by the repo API ([repository security advisories](https://github.com/AdguardTeam/AdGuardHome/security/advisories)).
- Privacy:
  - "does not collect any usage statistics, and does not use any web services unless you configure it to do so" ([README L425](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L425)).
  - But the update check contacts AdGuard servers by default ([KB FAQ › version error](https://adguard-dns.io/kb/adguard-home/faq/#version-error)), and WHOIS lookups for public client IPs are on by default ([config.go L408](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L408)).
- Resolver hardening named in the docs:
  - Access lists, per-subnet rate limiting, `refuse_any`, coalescing of identical pending requests, and disabling plain DNS on public servers ([KB Running securely](https://adguard-dns.io/kb/adguard-home/running-securely/); [KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns)).
  - DNS-rebinding protection is a filter list only (section 2) ([CHANGELOG L534](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L534)).
  - 0x20 case randomisation and response rate limiting (RRL) are not documented ([KB Configuration › dns](https://adguard-dns.io/kb/adguard-home/configuration/#dns); [KB Running securely](https://adguard-dns.io/kb/adguard-home/running-securely/)).

### 11. Performance claims and benchmarks

- **No published benchmarks or performance figures** were found: none for QPS, latency, memory or rule-count scaling in the README, KB, wiki or the AdGuard product page ([README](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md); [KB AdGuard Home](https://adguard-dns.io/kb/adguard-home/overview/); [adguard.com product page](https://adguard.com/en/adguard-home/overview.html)).
- The repo has a Go benchmark runner, but no published results ([scripts/make/go-bench.sh](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/scripts/make/go-bench.sh)).
- Performance-related defaults in source:
  - `max_goroutines` 300, raised after issues #2015 and #2257 ([config.go L303-L307](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L303-L307)).
  - Cache 4 MiB ([config.go L311](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L311)).
  - Rate limit 20 qps per subnet ([config.go L303-L312](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go#L303-L312)).
- A maintainer on regex rules: "If there are many thousands -- there is [a performance impact]. But a small number of regexes won't hurt" ([#1446 comment](https://github.com/AdguardTeam/AdGuardHome/issues/1446#issuecomment-619997771)).

### 12. Limitations, long-standing requests, roadmap

- Limits of DNS-level blocking:
  - Ads served from the same domain as content (YouTube, Twitch, sponsored posts) cannot be blocked ([README L185-L198](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L185-L198)).
  - A content-blocking proxy is promised "in the future" ([README L185-L198](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/README.md?plain=1#L185-L198); [KB FAQ › limitations](https://adguard-dns.io/kb/adguard-home/faq/#limitations)). It is [#1228](https://github.com/AdguardTeam/AdGuardHome/issues/1228), open with 140 👍 in the v0.109.0 milestone.
- Most-upvoted open feature requests on 2026-10-09 ([search](https://github.com/AdguardTeam/AdGuardHome/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc)):
  - Redundancy / two instances ([#573](https://github.com/AdguardTeam/AdGuardHome/issues/573), 154).
  - Content-blocking proxy ([#1228](https://github.com/AdguardTeam/AdGuardHome/issues/1228), 140).
  - PROXY protocol ([#2798](https://github.com/AdguardTeam/AdGuardHome/issues/2798), 95).
  - NextDNS-style security features: typosquatting, DGA and newly-registered-domain blocking, etc. ([#1446](https://github.com/AdguardTeam/AdGuardHome/issues/1446), 74).
  - Separate TTL for rewrites ([#1518](https://github.com/AdguardTeam/AdGuardHome/issues/1518), 74).
  - DHCP on multiple interfaces ([#3539](https://github.com/AdguardTeam/AdGuardHome/issues/3539), 71).
  - Settings import/export ([#1147](https://github.com/AdguardTeam/AdGuardHome/issues/1147), 61).
  - Prometheus ([#516](https://github.com/AdguardTeam/AdGuardHome/issues/516), 55).
  - ECS as client IP ([#1727](https://github.com/AdguardTeam/AdGuardHome/issues/1727), 54).
  - Cache prefetch ([#1259](https://github.com/AdguardTeam/AdGuardHome/issues/1259), 43).
  - 2FA ([#1667](https://github.com/AdguardTeam/AdGuardHome/issues/1667), 43).
  - ODoH ([#2406](https://github.com/AdguardTeam/AdGuardHome/issues/2406), 40).
  - Per-client blocklists ([#8029](https://github.com/AdguardTeam/AdGuardHome/issues/8029), 39).
  - ACME ([#1603](https://github.com/AdguardTeam/AdGuardHome/issues/1603), 35).
  - User accounts ([#997](https://github.com/AdguardTeam/AdGuardHome/issues/997), 30).
  - Client groups ([#2527](https://github.com/AdguardTeam/AdGuardHome/issues/2527), 30).
  - Recursive resolver ([#790](https://github.com/AdguardTeam/AdGuardHome/issues/790), 26).
- Other gaps confirmed above: no local DNSSEC validation ([#1579](https://github.com/AdguardTeam/AdGuardHome/issues/1579)), no query-log export ([#3389](https://github.com/AdguardTeam/AdGuardHome/issues/3389)), no user-defined blocked services ([#1692](https://github.com/AdguardTeam/AdGuardHome/issues/1692)), no timed lists ([#1203](https://github.com/AdguardTeam/AdGuardHome/issues/1203)), no nftables sets ([#5136](https://github.com/AdguardTeam/AdGuardHome/issues/5136)).
- Roadmap:
  - There is no roadmap document in the README, KB or wiki. GitHub milestones are the only public signal ([milestones](https://github.com/AdguardTeam/AdGuardHome/milestones)).
  - **v1.0.0**: 13 open issues. They include a recursive resolver (#790), cache prefetch (#1259), query-log export (#1176), PROXY protocol (#2798), DoH only for configured clients (#2861), mDNS announcement (#1118), IP lists in access settings (#1032), DHCP on Windows (#616), replacing dnsmasq on OpenWrt (#1464), daemonize (#2701), strict file modes (#3200), IDN upstreams (#2915) ([milestone v1.0.0](https://github.com/AdguardTeam/AdGuardHome/milestone/15)).
  - **v0.108.0**: 76 open. They include HA (#573), user accounts (#997), changing the password in the UI (#1321), probes (#1979), ECS as client IP (#1727), and the redesign tracking issue (#2554) ([milestone v0.108.0](https://github.com/AdguardTeam/AdGuardHome/milestone/24)).
  - **v0.109.0**: 29 open, e.g. content-blocking proxy, ODoH, ACME, 2FA, query-log export, custom blocked services, GeoIP/ASN client blocking ([milestone v0.109.0](https://github.com/AdguardTeam/AdGuardHome/milestone/29)).
  - **v0.110.0**: 3 open (SOCKS proxy, partially disabling statistics, timed lists) ([milestone v0.110.0](https://github.com/AdguardTeam/AdGuardHome/milestone/36)).
  - **v0.107.80**: 32 open ([milestone v0.107.80](https://github.com/AdguardTeam/AdGuardHome/milestone/52)).
  - Milestone labels look stale: v0.108.0 never shipped a stable release, and the beta line moved to v1.0.0 numbering. Issue targets are therefore weak evidence of timing ([release v1.0.0-b.1](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v1.0.0-b.1); [CHANGELOG L10](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/CHANGELOG.md?plain=1#L10)).

## Pi-hole

As of 2026-10-09, Pi-hole Core v6.4.3 / FTL v6.7.1 / Web v6.6 (Core and Web released 2026-07-06, FTL released 2026-09-19)

Scope and pinning: code citations point to the release tags (FTL `v6.7.1`, Core `v6.4.3`, Web `v6.6`), to docker-pi-hole `master` at `a4b24e1`, to the docs site (source commit `ea18203`, 2026-09-30), and, where marked "unreleased", to FTL `development` at `91fadcf` (2026-10-09). "Release" below means FTL v6.7.1 unless stated otherwise.

### 1. Version, licence, platforms, install

- Latest releases: Core v6.4.3 (2026-07-06), FTL v6.7.1 (2026-09-19), Web v6.6 (2026-07-06), Docker image 2026.09.0 (2026-09-19, "Nothing Docker specific, tagging to include FTL v6.7.1"). Sources: [Core v6.4.3](https://github.com/pi-hole/pi-hole/releases/tag/v6.4.3), [FTL v6.7.1](https://github.com/pi-hole/FTL/releases/tag/v6.7.1), [Web v6.6](https://github.com/pi-hole/web/releases/tag/v6.6), [Docker 2026.09.0](https://github.com/pi-hole/docker-pi-hole/releases/tag/2026.09.0)
- The v6 line (embedded web server, REST API, `pihole.toml`) started with FTL v6.0 and Core v6.0 on 2025-02-18. Sources: [FTL v6.0](https://github.com/pi-hole/FTL/releases/tag/v6.0), [Core v6.0](https://github.com/pi-hole/pi-hole/releases/tag/v6.0)
- Release cadence in 2026: FTL v6.5 (02-17), v6.6 (04-03), v6.6.1 (04-24), v6.6.2 (05-11, dnsmasq CVE fixes), v6.7 (07-06), v6.7.1 (09-19); a v6.7.2 maintenance release is in draft. Sources: [FTL releases](https://github.com/pi-hole/FTL/releases), [FTL PR #3206 (draft v6.7.2)](https://github.com/pi-hole/FTL/pull/3206)
- Licence: Core, FTL, Web and docker-pi-hole are EUPL v1.2; the docs are CC BY-SA 4.0; the embedded dnsmasq sources keep their GPL v2/v3 header. Sources: [Core LICENSE](https://github.com/pi-hole/pi-hole/blob/v6.4.3/LICENSE), [FTL LICENSE](https://github.com/pi-hole/FTL/blob/v6.7.1/LICENSE#L1-L10), [Web LICENSE](https://github.com/pi-hole/web/blob/v6.6/LICENSE), [docs LICENSE](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/LICENSE), [dnsmasq.h header](https://github.com/pi-hole/FTL/blob/v6.7.1/src/dnsmasq/dnsmasq.h#L1-L15)
- Languages: Core is Bash, FTL is C (with embedded dnsmasq, SQLite, CivetWeb and Lua), Web is JavaScript plus Lua server pages (`.lp`). Sources: [GitHub languages API, pi-hole](https://api.github.com/repos/pi-hole/pi-hole/languages), [FTL](https://api.github.com/repos/pi-hole/FTL/languages), [web](https://api.github.com/repos/pi-hole/web/languages), [docs: webserver](https://docs.pi-hole.net/ftldns/webserver/#ftls-embedded-webserver-and-lua-server-pages)
- Embedded component versions: dnsmasq v2.93 and SQLite 3.53.1 (FTL v6.7), Lua 5.5 (FTL v6.5); TLS in the release uses mbedTLS. Sources: [FTL v6.7 notes](https://github.com/pi-hole/FTL/releases/tag/v6.7), [FTL v6.5 notes](https://github.com/pi-hole/FTL/releases/tag/v6.5), [FTL CMakeLists L551-L556](https://github.com/pi-hole/FTL/blob/v6.7.1/src/CMakeLists.txt#L551-L556)
- Officially supported OSes: Alpine, Armbian, Debian, CentOS Stream, Fedora, Raspberry Pi OS, Ubuntu ("only actively maintained versions"); Linux only. Source: [docs: prerequisites](https://docs.pi-hole.net/main/prerequisites/#supported-operating-systems)
- Init systems: the prerequisites page names systemd and sysvinit only, but Core also ships and uses an OpenRC script (Alpine). The two sources disagree. Sources: [docs: prerequisites](https://docs.pi-hole.net/main/prerequisites/#software), [pihole-FTL.openrc](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole-FTL.openrc), [basic-install.sh L1274-L1275](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L1274-L1275)
- `pihole-FTL` architectures: x86_64 (amd64, i686), armv6, armv7, armv8 (aarch64), riscv64; others must build from source. Release assets also include an `amd64-clang` build. Sources: [docs: prerequisites](https://docs.pi-hole.net/main/prerequisites/#binary-architecture), [FTL v6.7.1 assets](https://github.com/pi-hole/FTL/releases/tag/v6.7.1)
- Docker image platforms: linux/amd64, 386, arm/v6, arm/v7, arm64, riscv64; Alpine 3.24 base; published as `pihole/pihole` and `ghcr.io/pi-hole/pihole`. Sources: [build-and-publish.yml L74-L79](https://github.com/pi-hole/docker-pi-hole/blob/a4b24e115ee161e9f991f955d030dc8f24257289/.github/workflows/build-and-publish.yml#L74-L79), [Dockerfile L4](https://github.com/pi-hole/docker-pi-hole/blob/a4b24e115ee161e9f991f955d030dc8f24257289/src/Dockerfile#L4)
- Install methods: `curl -sSL https://install.pi-hole.net | bash`, clone and run `basic-install.sh`, download and run the installer, or Docker (Compose or `docker run`). Sources: [docs: basic install](https://docs.pi-hole.net/main/basic-install/), [docs: Docker](https://docs.pi-hole.net/docker/)
- Packages: the docs list no distribution packages of Pi-hole itself; the installer builds a local `pihole-meta` deb/rpm/apk meta-package only to pull dependencies, and downloads the FTL binary separately. Sources: [docs: basic install](https://docs.pi-hole.net/main/basic-install/), [basic-install.sh L114-L160](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L114-L160), [L1873-L1890](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L1873-L1890)
- Updates: `pihole -up` on bare metal; in Docker `pihole -up` and `pihole -r` are disabled and you replace the container. Sources: [docs: updating](https://docs.pi-hole.net/main/update/), [docs: Docker upgrading](https://docs.pi-hole.net/docker/upgrading/#upgrading-repairing)
- Resource needs: minimum 2 GB free disk (4 GB recommended) and 512 MB RAM; the page was last updated 2020-05-25. Static IP required. Sources: [docs: prerequisites](https://docs.pi-hole.net/main/prerequisites/#hardware), [prerequisites.md front matter](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/docs/main/prerequisites.md?plain=1#L1-L12)
- Ports: 53 TCP/UDP (DNS), 67/547 UDP (optional DHCP/DHCPv6), 80/443 TCP (web/API, falls back to 8080/8443), 123 UDP (optional NTP). Source: [docs: prerequisites](https://docs.pi-hole.net/main/prerequisites/#ports)

### 2. Filtering

- Two list kinds are subscribable: block lists (into table `gravity`) and, since v6.0, allow lists (into table `antigravity`). Sources: [docs: domain database](https://docs.pi-hole.net/database/domain-database/#gravity-tables-gravity-and-antigravity), [gravity.db.sql L27-L62](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/gravity.db.sql#L27-L62)
- List sources may be `http://`, `https://` or `file://`; downloads use curl with compression, ETag and If-Modified-Since. Sources: [gravity.sh L515-L528](https://github.com/pi-hole/pi-hole/blob/v6.4.3/gravity.sh#L515-L528), [L630-L654](https://github.com/pi-hole/pi-hole/blob/v6.4.3/gravity.sh#L630-L654), [L724-L764](https://github.com/pi-hole/pi-hole/blob/v6.4.3/gravity.sh#L724-L764)
- Accepted list formats (FTL's parser): hosts files (IPv4/IPv6 tokens are skipped), plain one-domain-per-line lists, and ABP-style `||domain^` (block lists) or `@@||domain^` (allow lists). Lines starting with `!`, `#`, `;` or `[` are comments/headers; lines with cosmetic selectors (`##`, `#$#`, `#@#`, `#?#`) or AdGuard JS (`#%#`) are dropped. Source: [gravity-parseList.c L192-L229](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L192-L229), [L424-L476](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L424-L476)
- ABP limits: an ABP entry must start with `||` (or `@@||`), end with `^` and contain a valid domain; anything else (modifiers such as `$important`/`$client`/`$dnsrewrite`, `*` wildcards, paths, regex rules) fails validation and is counted as an invalid domain. Source: [gravity-parseList.c L192-L229](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L192-L229), [L108-L188](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L108-L188), [L493-L570](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L493-L570)
- Domain validation: lower-cased, max 255 characters, labels max 63, at least one dot for exact entries; UTF-8 IDNs are rejected in lists (the FAQ tells users to ask list maintainers for punycode). Sources: [gravity-parseList.c L108-L188](https://github.com/pi-hole/FTL/blob/v6.7.1/src/tools/gravity-parseList.c#L108-L188), [docs: FAQ](https://docs.pi-hole.net/main/faq/#pi-holes-gravity-complains-about-invalid-idn-domains)
- Match semantics: plain list entries match the exact name only; ABP entries match the name and all subdomains (FTL queries each suffix as `||suffix^`). ABP suffix lookups only run if some list contained ABP entries. Source: [gravity-db.c L1670-L1755](https://github.com/pi-hole/FTL/blob/v6.7.1/src/database/gravity-db.c#L1670-L1755)
- Lookup implementation: list lookups are SQLite queries against `gravity.db` views joined with the client's groups; each domain's verdict is then kept in an in-memory "blocking cache" until lists reload. Sources: [gravity-db.c L1403](https://github.com/pi-hole/FTL/blob/v6.7.1/src/database/gravity-db.c#L1403), [L1670-L1705](https://github.com/pi-hole/FTL/blob/v6.7.1/src/database/gravity-db.c#L1670-L1705), [docs: signals](https://docs.pi-hole.net/ftldns/signals/#real-time-signal-0-35)
- Manual lists (`domainlist`): exact allow (type 0), exact deny (1), regex allow (2), regex deny (3), each with enabled flag and comment. Source: [docs: domain database](https://docs.pi-hole.net/database/domain-database/#domain-tables-domainlist)
- Decision priority: exact allow > regex allow > exact deny > subscribed allow lists > subscribed block lists > regex deny. Source: [docs: domain database](https://docs.pi-hole.net/database/domain-database/#priorities)
- "Wildcard" entries are not a separate type: `pihole --wild example.com` stores the regex `(\.|^)example\.com$`. Source: [list.sh L60-L67](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Scripts/list.sh#L60-L67)
- Regex engine: POSIX ERE (TRE) with case-insensitive matching, approximate (`agrep`-style) matching, inline comments `(?#...)`, back-references and `\d`/`\D`. Sources: [docs: regex](https://docs.pi-hole.net/regex/), [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#comments), [docs: approximate](https://docs.pi-hole.net/regex/approximate/)
- Regex extension `;querytype=`: one or more types, with `!` negation (e.g. `.*;querytype=!A,AAAA`); `OTHER` matches types not listed elsewhere. Source: [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#only-match-specific-query-types)
- Regex extension `;invert`: match everything except the pattern. Source: [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#invert-matching)
- Regex extension `;reply=`: `nodata`, `nxdomain`, `refused`, `none` (drop), `ip`, a literal IPv4 and/or IPv6 address. Source: [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#specify-reply-type)
- Undocumented: FTL's parser also accepts `;reply=CNAME,<target>` and synthesises a CNAME answer; the docs page does not list it (not tested here). Sources: [regex.c L246-L330](https://github.com/pi-hole/FTL/blob/v6.7.1/src/regex.c#L246-L330), [dnsmasq_interface.c L458](https://github.com/pi-hole/FTL/blob/v6.7.1/src/dnsmasq_interface.c#L458), [L604-L610](https://github.com/pi-hole/FTL/blob/v6.7.1/src/dnsmasq_interface.c#L604-L610), [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#specify-reply-type)
- Gravity: `pihole -g` downloads all enabled lists, parses them into a temporary `gravity.db`, builds indexes and swaps it in; tables are flushed and rebuilt on every run. Sources: [docs: pihole command](https://docs.pi-hole.net/main/pihole-command/#gravity), [gravity.sh L118-L161](https://github.com/pi-hole/pi-hole/blob/v6.4.3/gravity.sh#L118-L161), [docs: domain database](https://docs.pi-hole.net/database/domain-database/#gravity-tables-gravity-and-antigravity)
- Update schedule: weekly cron job on Sunday at a random time between 03:01 and 04:58, set at install; same in Docker. Not configurable in `pihole.toml` or the UI (open feature request). Sources: [pihole.cron L17-L21](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole.cron#L17-L21), [basic-install.sh L1514-L1525](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L1514-L1525), [bash_functions.sh L82-L94](https://github.com/pi-hole/docker-pi-hole/blob/a4b24e115ee161e9f991f955d030dc8f24257289/src/bash_functions.sh#L82-L94), [Discourse: gravity frequency from GUI](https://discourse.pi-hole.net/t/change-gravity-update-frequency-from-gui/23598)
- While `gravity.db` is busy, `dns.replyWhenBusy` decides: `ALLOW` (default), `BLOCK`, `REFUSE` or `DROP`. Source: [config.c L484-L498](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L484-L498)
- Blocking modes: `NULL` (default, `0.0.0.0`/`::`), `IP_NODATA_AAAA`, `IP`, `NX` (NXDOMAIN), `NODATA`. Sources: [config.c L669-L684](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L669-L684), [docs: blocking mode](https://docs.pi-hole.net/ftldns/blockingmode/)
- Disagreement: the blocking-mode page says `pihole-FTL --config dns.blocking.mode NXDOMAIN`, but FTL's parser accepts only `NX`. Sources: [docs: NXDOMAIN mode](https://docs.pi-hole.net/ftldns/blockingmode/#pi-holes-nxdomain-blocking-mode), [datastructure.c L966-L1001](https://github.com/pi-hole/FTL/blob/v6.7.1/src/datastructure.c#L966-L1001)
- Blocked-answer TTL `dns.blockTTL` defaults to 2 s; IP mode addresses can be pinned with `dns.reply.blocking.IPv4/IPv6`. Sources: [config.c L500-L505](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L500-L505), [L748-L771](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L748-L771)
- Blocked answers carry EDNS Extended DNS Error 15 (Blocked) plus a reason text by default (`dns.blocking.edns = TEXT`; also `CODE`, `NONE`). Source: [config.c L686-L700](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L686-L700)
- Deep CNAME inspection (`dns.CNAMEdeepInspect`, default on): a reply is blocked if any name in its CNAME chain is on a list; logged as statuses 9-11 with the offending domain. Sources: [config.c L431-L435](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L431-L435), [docs: query database statuses](https://docs.pi-hole.net/database/query-database/#supported-status-types)
- Upstream-block detection: replies with known block-page IPs, `0.0.0.0`/`::`, NXDOMAIN without RA, or EDE 15 are counted as "blocked by upstream" and cached for `dns.cache.upstreamBlockedTTL` (86400 s). Sources: [docs: query database statuses](https://docs.pi-hole.net/database/query-database/#supported-status-types), [docs: DNS cache](https://docs.pi-hole.net/ftldns/dns-cache/#caching-of-queries-blocked-upstream-dnscacheupstreamblockedttl)
- Special domains (all default on): `use-application-dns.net` NXDOMAIN (Firefox canary), `mask.icloud.com`/`mask-h2.icloud.com` NXDOMAIN (iCloud Private Relay), NODATA for `resolver.arpa` (blocks DDR, RFC 9462). Source: [config.c L702-L719](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L702-L719)
- `dns.blockESNI` (NXDOMAIN for `_esni.` subdomains of blocked domains) exists and defaults to on in the release; it is removed on `development`. Sources: [config.c L437-L441](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L437-L441), [FTL PR #3023](https://github.com/pi-hole/FTL/pull/3023)
- Safe search: not supported. There is no config key or API endpoint for it; Discourse staff point users to hand-made local DNS/CNAME records. Sources: [OpenAPI path list](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L72-L291), [Discourse: toggle safesearch](https://discourse.pi-hole.net/t/web-interface-toggle-safesearch/39477), [Discourse: safe search for groups](https://discourse.pi-hole.net/t/safe-search-for-groups/46023/4)
- Blocked services (one-click service toggles as in AdGuard Home): not supported; there is no such endpoint or config key. Source: [OpenAPI path list](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L72-L291)
- Schedules: not supported. Groups have only `name`, `comment`, `enabled`; time-based blocking is an open request since 2017 (staff: "Sponsorships for features you require are acceptable"). Sources: [groups.yaml L265-L327](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/groups.yaml#L265-L327), [Discourse: timed DNS queries](https://discourse.pi-hole.net/t/timed-dns-queries-block-dns-based-on-time/3495/11), [Discourse: scheduled blocking (2026)](https://discourse.pi-hole.net/t/feature-request-scheduled-time-based-blocking-per-domain-group-or-client/87794)
- Temporary disable: global only. API `POST /api/dns/blocking` with `{blocking:false, timer:60}`; CLI `pihole disable 5m`; UI presets 10 s, 30 s, 5 min, custom, indefinitely. A per-domain "temporarily allow" is an open request. Sources: [dns.yaml L11-L35](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/dns.yaml#L11-L35), [docs: enable/disable](https://docs.pi-hole.net/main/pihole-command/#enable-disable), [sidebar.lp L88-L120](https://github.com/pi-hole/web/blob/v6.6/scripts/lua/sidebar.lp#L88-L120), [Discourse: temporarily allow](https://discourse.pi-hole.net/t/add-a-temporarily-allow-feature/3947)

### 3. Clients and groups

- Model: table `group` (name, description, enabled) plus linking tables `adlist_by_group`, `domainlist_by_group` and `client_by_group`. Lists, domains and clients can each be in any number of groups. Sources: [docs: group management (DB)](https://docs.pi-hole.net/database/domain-database/groups/), [gravity.db.sql L4-L98](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/gravity.db.sql#L4-L98)
- Group `Default` (id 0) is assigned to every new list, domain and client and cannot be deleted; disabling it disables blocking for all unmanaged clients. Sources: [docs: group management](https://docs.pi-hole.net/group_management/), [group_management/example.md L17](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/docs/group_management/example.md?plain=1#L17)
- Client identifiers: IPv4/IPv6 address, CIDR subnet (any prefix length), MAC address, hostname, or interface (`:eth0`). First match wins; hostname/interface matching may take time; MAC matching works only one hop away. Sources: [groups-clients.lp L47-L58](https://github.com/pi-hole/web/blob/v6.6/groups-clients.lp#L47-L58), [clients.yaml L355](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/clients.yaml#L355), [docs: client table](https://docs.pi-hole.net/database/domain-database/#client-table-client)
- Clients behind a forwarder: FTL can take the client from EDNS Client Subnet (`dns.EDNS0ECS`, default on) and parses EDNS MAC (byte and text) and CPE-ID options. Sources: [config.c L443-L447](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L443-L447), [edns0.c L22-L42](https://github.com/pi-hole/FTL/blob/v6.7.1/src/edns0.c#L22-L42)
- Per group: subscribed block lists, subscribed allow lists, exact and regex allow/deny entries. Because regex entries are group-scoped, `;querytype=` and `;reply=` behaviour can differ per group. Sources: [docs: group management](https://docs.pi-hole.net/group_management/), [docs: regex extensions](https://docs.pi-hole.net/regex/pi-hole/#only-match-specific-query-types)
- Not per group (single global value in `pihole.toml`): blocking on/off and its timer, blocking mode, block TTL, upstream servers, local DNS and CNAME records, conditional forwarding, rate limit, privacy level, special domains, CNAME inspection, cache settings. Sources: [config.c key list L423-L788](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L788), [L1396-L1410](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1396-L1410), [groups.yaml L265-L327](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/groups.yaml#L265-L327)
- Group changes only enable/disable things manually; there is no group timer or schedule. Source: [groups.yaml L265-L327](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/groups.yaml#L265-L327)

### 4. DNS resolution

- FTL embeds Pi-hole's own fork of dnsmasq ("dnsmasq with Pi-hole's special sauce") and hooks it; Pi-hole keeps resolver changes minimal so upstream security patches still apply. Sources: [docs: DNS resolver](https://docs.pi-hole.net/ftldns/dns-resolver/), [FTL README](https://github.com/pi-hole/FTL/blob/v6.7.1/README.md)
- FTL generates `/etc/pihole/dnsmasq.conf` from `pihole.toml` (`no-resolv`, one `server=` per upstream, `port=`, `cache-size=` and so on). Sources: [dnsmasq_config.c L403-L425](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L403-L425), [dnsmasq_config.h L32-L40](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.h#L32-L40)
- Upstreams (`dns.upstreams`): array of IPs or hostnames with optional `#port`; plain DNS only in the release; empty by default (no forwarding until set). Source: [config.c L423-L429](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L429)
- The installer offers 8 preset providers plus Custom; the upstream-providers page says both "nine options" and "1 of the 7 preset providers" (the docs disagree with themselves and with the installer). Sources: [basic-install.sh L45-L56](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L45-L56), [docs: upstream providers](https://docs.pi-hole.net/guides/dns/upstream-dns-providers/)
- Upstream selection: FTL keeps the fastest server for 1000 queries or 10 minutes (dnsmasq default: 50 queries / 10 s) and retries all servers on SERVFAIL, REFUSED or timeout. Source: [docs: DNS resolver](https://docs.pi-hole.net/ftldns/dns-resolver/#improve-detection-algorithm-for-determining-the-best-forward-destination)
- Conditional forwarding (`dns.revServers`): array of `"<enabled>,<cidr>,<server>[#port][,<domain>]"`, rendered as `rev-server=` plus `server=/<domain>/<server>`. Sources: [config.c L606-L613](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L606-L613), [dnsmasq_config.c L600-L630](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L600-L630)
- Local domain `dns.domain.name` (default `lan`) is never forwarded while `dns.domain.local` is true (default), unless a rev-server exists for it. Source: [config.c L615-L629](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L615-L629)
- Domain-specific upstreams: no first-class key. Options are a rev-server with a domain, `server=/domain/ip` in `misc.dnsmasq_lines` (since v6.7.1 settable only via `pihole.toml`, env var or CLI, not the API/UI), or files in `/etc/dnsmasq.d` with `misc.etc_dnsmasq_d` (default off). Sources: [config.c L1433-L1446](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1433-L1446), [FTL v6.7.1 notes](https://github.com/pi-hole/FTL/releases/tag/v6.7.1)
- Per-client or per-group upstreams: not supported (no such key). Source: [config.c L423-L788](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L788)
- Local DNS records: `dns.hosts` (HOSTS format, `"IP name [name...]"`), `dns.cnameRecords` (`"<cname>,<target>[,<TTL>]"`), `dns.hostRecord` (A+AAAA+PTR); written to `/etc/pihole/hosts/custom.list` via `hostsdir`. Sources: [config.c L507-L512](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L507-L512), [L550-L556](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L550-L556), [L583-L589](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L583-L589), [dnsmasq_config.h L36-L37](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.h#L36-L37)
- Wildcard local records: not supported ("intentionally designed as simple HOSTS-like records", staff); the workaround is dnsmasq `address=/domain/ip`, which the Docker docs show via `FTLCONF_misc_dnsmasq_lines`. Sources: [Discourse: wildcards in local DNS](https://discourse.pi-hole.net/t/support-wildcards-in-local-dns-records/32098/40), [docs: Docker configuration](https://docs.pi-hole.net/docker/configuration/#configuring-ftl-via-the-environment)
- Local record order: device hostname and `pi.hole`, then `/etc/dnsmasq.d`, then `/etc/hosts`, then the local DNS list. The FAQ still names `/etc/pihole/custom.list`; v6 code writes `/etc/pihole/hosts/custom.list` and treats the old path as legacy (disagreement). Sources: [docs: FAQ](https://docs.pi-hole.net/main/faq/#in-which-order-are-locally-defined-dns-records-used), [dnsmasq_config.h L36-L39](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.h#L36-L39)
- Cache: dnsmasq cache, `dns.cache.size` 10000 (0 disables, minimum 150 with DNSSEC), not persistent across restarts, cleared on SIGHUP; help text warns lookup speed degrades above 10,000 entries. Sources: [docs: DNS cache](https://docs.pi-hole.net/ftldns/dns-cache/), [config.c L631-L637](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L631-L637)
- Serve-stale: `dns.cache.optimizer` 3600 s (dnsmasq `use-stale-cache`); `dns.cache.rrtype` limits cached types (default `ANY`). No key sets a minimum or maximum cache TTL. Sources: [config.c L639-L661](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L639-L661), [dnsmasq_config.c L513-L518](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L513-L518), [docs: optimizer](https://docs.pi-hole.net/ftldns/dns-cache/#query-cache-optimizer-dnscacheoptimizer)
- Cache metrics: size, active, insertions, evictions, expired, immortal; on Settings > System and via `dig chaos txt cachesize.bind` etc. Source: [docs: cache metrics](https://docs.pi-hole.net/ftldns/dns-cache/#cache-metrics)
- DNSSEC: validation by the embedded dnsmasq when `dns.dnssec = true` (default false), with the 2017 and 2024 root KSK trust anchors hard-coded; per-query status SECURE/INSECURE/BOGUS/ABANDONED/TRUNCATED. Sources: [config.c L535-L540](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L535-L540), [dnsmasq_config.c L490-L503](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L490-L503), [docs: DNSSEC status](https://docs.pi-hole.net/database/query-database/#dnssec-status)
- Rate limiting: per client, 1000 queries per 60 s by default; excess queries get REFUSED until the interval ends; 0/0 disables. Source: [config.c L775-L788](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L775-L788)
- Concurrent forwarded queries are capped by dnsmasq; the Docker docs suggest `FTL_CMD="no-daemon -- --dns-forward-max 300"` on high-load setups. Sources: [docs: Docker advanced variables](https://docs.pi-hole.net/docker/configuration/#advanced-variables), [docs: dnsmasq warnings](https://docs.pi-hole.net/ftldns/dnsmasq_warn/)
- Listening modes: `LOCAL` (default, dnsmasq `local-service`), `SINGLE`, `BIND`, `ALL`, `NONE`; FTL binds the wildcard address except in `BIND`. Sources: [config.c L558-L574](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L558-L574), [docs: interfaces](https://docs.pi-hole.net/ftldns/interfaces/)
- Other resolver switches: `bogusPriv` (default on), `domainNeeded` (default off), `expandHosts`, `localise`, `piholePTR`. Sources: [config.c L514-L533](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L514-L533), [L467-L482](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L467-L482), [L599-L604](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L599-L604)
- DNS rebinding protection: FTL's generated config does not emit dnsmasq `stop-dns-rebind` (it is only reachable through custom dnsmasq lines); the docs mention it only as a dnsmasq warning. Sources: [dnsmasq_config.c (emitted options)](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c), [docs: dnsmasq warnings](https://docs.pi-hole.net/ftldns/dnsmasq_warn/)
- EDNS: ECS used for client identification (above), EDE on blocked replies (above); FTL's generated config does not add ECS or MAC to forwarded queries. Sources: [edns0.c L202](https://github.com/pi-hole/FTL/blob/v6.7.1/src/edns0.c#L202), [dnsmasq_config.c](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c)
- IPv6: blocks A and AAAA (`::` in NULL mode), accepts IPv6 upstreams, and can run router advertisements through DHCP (section 6). Sources: [docs: overview](https://docs.pi-hole.net/), [docs: NULL mode](https://docs.pi-hole.net/ftldns/blockingmode/#pi-holes-unspecified-ip-or-null-blocking-mode)
- Recursion: not built in. The official guide installs Unbound on `127.0.0.1#5335` (with DNSSEC in Unbound) and sets it as Pi-hole's only upstream. Source: [docs: unbound](https://docs.pi-hole.net/guides/dns/unbound/#configure-pi-hole)
- Config changes and restarts: 62 of the 167 config keys carry `FLAG_RESTART_FTL`, including `dns.upstreams`, `dns.cnameRecords`, `dns.revServers`, `dns.cache.size` and all `dhcp.*` keys. FTL watches `/etc/pihole` with inotify and re-reads `pihole.toml` when it is written. Sources: [config.c (FLAG_RESTART_FTL)](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1451), [config.h L103-L105](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.h#L103-L105), [inotify.c L42-L49](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/inotify.c#L42-L49), [gc.c L705-L709](https://github.com/pi-hole/FTL/blob/v6.7.1/src/gc.c#L705-L709)
- List reloads without a cache flush: `pihole reloadlists` (or RT signal 0) re-reads lists and regexes; `pihole reloaddns` also flushes the DNS cache. Sources: [docs: reload lists](https://docs.pi-hole.net/main/pihole-command/#reload-lists), [docs: signals](https://docs.pi-hole.net/ftldns/signals/#real-time-signal-0-35)

### 5. Encrypted DNS

- Release (FTL v6.7.1): FTL neither serves DoH, DoT or DoQ nor forwards over them. There is no config key for it, and staff confirmed in July 2026 that it was out of scope until then. Sources: [config.c key list](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1690), [Discourse: DoT (staff, 2026-07-12)](https://discourse.pi-hole.net/t/implement-dns-over-tls-capability-in-pi-hole/8722/79)
- Officially documented workaround for encrypted upstreams: `cloudflared` (DoH). The page now warns that `proxy-dns` is deprecated, stops working for cloudflared versions after 2026-02-02, and is not recommended for new installs. Source: [docs: cloudflared](https://docs.pi-hole.net/guides/dns/cloudflared/)
- Other documented workarounds: `dnscrypt-proxy` (DoH and other encrypted protocols to upstream) and Unbound (recursive). Sources: [docs: dnscrypt-proxy](https://docs.pi-hole.net/guides/dns/dnscrypt-proxy/), [docs: unbound](https://docs.pi-hole.net/guides/dns/unbound/)
- ODoH and a DNSCrypt server: not supported or documented (no key, no docs page). Sources: [config.c key list](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1690), [docs nav](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/mkdocs.yml#L110-L215)
- Unreleased (FTL `development`): native DoT/DoH upstreams (`tls://`, `https://`, `sni@ip` pinning, fail-closed certificate checks, EDNS padding to 128 octets, `dns.upstreamCA`), merged 2026-07-17. Sources: [FTL PR #2940](https://github.com/pi-hole/FTL/pull/2940), [dev config.c L621-L627](https://github.com/pi-hole/FTL/blob/91fadcf795325edef55a3e9097778b1c45e266cb/src/config/config.c#L621-L627)
- Unreleased: inbound DoT on 853 and DoH at `/dns-query` on the HTTPS port (HTTP/1.1, /2, /3), with keys `dns.dot` and `dns.doh` defaulting to on; merged 2026-08-05. Sources: [FTL PR #2989](https://github.com/pi-hole/FTL/pull/2989), [FTL PR #2976](https://github.com/pi-hole/FTL/pull/2976), [dev config.c L629-L641](https://github.com/pi-hole/FTL/blob/91fadcf795325edef55a3e9097778b1c45e266cb/src/config/config.c#L629-L641)
- Unreleased: TLS library moving from mbedTLS to OpenSSL (merged); DoQ upstream and server (UDP/853) is an open PR. Sources: [FTL PR #2941](https://github.com/pi-hole/FTL/pull/2941), [FTL PR #3000](https://github.com/pi-hole/FTL/pull/3000)
- The maintainers' v6.7.2 draft explicitly excludes "the v7 work (OpenSSL, DoT/DoH, the terminator, ...)", so this ships no earlier than the next major release; no date is given. Sources: [FTL PR #3206](https://github.com/pi-hole/FTL/pull/3206), [Discourse: DoT (staff)](https://discourse.pi-hole.net/t/implement-dns-over-tls-capability-in-pi-hole/8722/79)

### 6. DHCP server

- Embedded dnsmasq DHCP, off by default (`dhcp.active`). When on, FTL always writes `dhcp-authoritative` and one IPv4 `dhcp-range` (start, end, optional netmask, optional lease time) plus the router option. Sources: [config.c L790-L836](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L790-L836), [dnsmasq_config.c L741-L765](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L741-L765)
- Default lease time: 1 hour (IPv4) and 1 day (IPv6) when unset. Source: [config.c L829-L835](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L829-L835)
- Static leases (`dhcp.hosts`): dnsmasq `dhcp-host` syntax with MAC, client-id, tags, IP, hostname, lease time and `ignore`. Source: [config.c L872-L880](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L872-L880)
- Other switches: `ignoreUnknownClients`, `rapidCommit` (RFC 4039), `multiDNS` (advertise the DNS server several times), `logging`. Sources: [config.c L844-L870](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L844-L870), [dnsmasq_config.c L766-L830](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L766-L830)
- IPv6: `dhcp.ipv6` adds router advertisements with `ra-names,ra-stateless` (SLAAC plus stateless DHCPv6 for DNS options). There is no key for a stateful DHCPv6 range. Source: [dnsmasq_config.c L784-L793](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L784-L793)
- The NTP server option is advertised automatically when FTL's IPv4 NTP server is on. Source: [dnsmasq_config.c L805-L810](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.c#L805-L810)
- Arbitrary DHCP options: no key; only via dnsmasq lines or `/etc/dnsmasq.d`. "Extra DHCP Server Options" is an open request. `pihole-FTL --list-dhcp4/--list-dhcp6` lists known options. Sources: [Discourse: extra DHCP options](https://discourse.pi-hole.net/t/extra-dhcp-server-options/6416), [args.c L924](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L924)
- API: `GET /api/dhcp/leases` and `DELETE /api/dhcp/leases/{ip}`; the Web v6.6 release reworked the static-lease UI. Sources: [main.yaml L279-L284](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L279-L284), [Web v6.6 notes](https://github.com/pi-hole/web/releases/tag/v6.6)
- Docker: DHCP needs host networking or a DHCP relay, plus `NET_ADMIN`. Sources: [docs: Docker DHCP](https://docs.pi-hole.net/docker/DHCP/), [docs: Docker capabilities](https://docs.pi-hole.net/docker/configuration/#note-on-capabilities)
- Diagnostics: `pihole-FTL dhcp-discover` finds other DHCP servers; dnsmasq can also provide TFTP. Sources: [args.c L1200-L1376](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L1200-L1376), [docs: FTLDNS](https://docs.pi-hole.net/ftldns/)

### 7. Query log and statistics

- Long-term database: SQLite `/etc/pihole/pihole-FTL.db`, written every `database.DBinterval` (60 s) and on exit. Sources: [docs: query database](https://docs.pi-hole.net/database/query-database/), [config.c L1020-L1025](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1020-L1025)
- Retention: `database.maxDBdays` defaults to 91 days (`365/4`) in code; 0 disables the database. Disagreement: the query-database page says the default is 365 days. Sources: [config.c L1009-L1018](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1009-L1018), [query-database.md L8](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/docs/database/query-database.md?plain=1#L8)
- In-memory history: the last 24 hours in 10-minute slots, re-imported from disk at start (`database.DBimport`). The history database is in memory by default; `database.forceDisk` moves it to disk. Sources: [FTL.h L86-L100](https://github.com/pi-hole/FTL/blob/v6.7.1/src/FTL.h#L86-L100), [config.c L1003-L1051](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1003-L1051)
- Stored per query: timestamp, type, status, domain, client IP, upstream, additional info (e.g. CNAME culprit or list ID), reply type, reply time, DNSSEC status, regex ID. Source: [docs: query table](https://docs.pi-hole.net/database/query-database/#query-table)
- Text log: `dns.queryLogging` (default on) writes dnsmasq's query log to `/var/log/pihole/pihole.log`, rotated daily with 5 copies kept; `FTL.log` and `webserver.log` rotate weekly with 3 copies. Sources: [config.c L576-L581](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L576-L581), [logrotate L1-L36](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/logrotate#L1-L36), [pihole.cron L23-L27](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole.cron#L23-L27)
- Privacy levels: 0 (show all), 1 (hide domains), 2 (hide domains and clients), 3 (anonymous: no query log, no long-term DB logging, most regex features lost). Sources: [docs: privacy levels](https://docs.pi-hole.net/ftldns/privacylevels/), [config.c L1396-L1410](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1396-L1410)
- Disagreement: the docs say the privacy level changes without restarting the resolver (and SIGHUP re-reads it); the `config.c` help text says changing it triggers an FTL restart, yet the key carries no restart flag. Sources: [docs: privacy levels](https://docs.pi-hole.net/ftldns/privacylevels/), [docs: SIGHUP](https://docs.pi-hole.net/ftldns/signals/#reload-everything-using-sighup), [config.c L1396-L1410](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1396-L1410)
- Exclusions: `webserver.api.excludeClients` and `excludeDomains` (regex) hide entries only from the API query log and top lists; `dns.ignoreLocalhost` hides localhost queries. A request to keep domains out of the log entirely is still open. Sources: [config.c L1263-L1276](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1263-L1276), [config.c L449-L453](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L449-L453), [Discourse: ignore domains in query log](https://discourse.pi-hole.net/t/option-to-ignore-domains-from-appearing-in-the-query-log/6319)
- Statistics API: summary, upstreams, top domains, top clients, query types, recent blocked, history and per-client history, each with a long-term `/database/` variant. Source: [main.yaml L87-L130](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L87-L130)
- Query log API: filters for time range, domain, client, upstream, type, status, reply, DNSSEC, cursor pagination, and `disk` to read the long-term DB. Source: [queries.yaml L34-L114](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/queries.yaml#L34-L114)
- Dashboards: the web UI has Dashboard, Query Log, Network, Interfaces and Pi-hole diagnosis (messages) pages. Sources: [web v6.6 tree](https://github.com/pi-hole/web/tree/v6.6), [sidebar.lp](https://github.com/pi-hole/web/blob/v6.6/scripts/lua/sidebar.lp)
- Network table: FTL parses the ARP/neighbour cache (`database.network.parseARPcache`), stores devices with MAC vendor (`macvendor.db`) and expires addresses after `database.network.expire` (default = maxDBdays). The API exposes `/network/devices`, `/gateway`, `/routes`, `/interfaces`. Sources: [config.c L1053-L1066](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1053-L1066), [main.yaml L246-L260](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L246-L260)
- Client names come from hourly PTR lookups (`resolver.refreshNames`, default `IPV4_ONLY`) and MAC or network-table fallbacks. Source: [config.c L961-L1001](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L961-L1001)

### 8. Interfaces

- Web UI (v6): served by FTL's embedded CivetWeb as Lua server pages (no lighttpd/PHP), AdminLTE-based, at `/admin/`. Pages cover dashboard, query log, groups/clients/domains/lists, settings (system, DNS, DHCP, API, privacy, Teleporter, local DNS records, "All settings"), tail log, gravity update, list search, interfaces, network. Sources: [Web README](https://github.com/pi-hole/web/blob/v6.6/README.md), [web v6.6 tree](https://github.com/pi-hole/web/tree/v6.6), [docs: webserver](https://docs.pi-hole.net/ftldns/webserver/)
- UI themes: auto, light, dark, darker, two high-contrast themes, and LCARS. Source: [config.c L1188-L1201](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1188-L1201)
- Web server ports: default `80o,443os,[::]:80o,[::]:443os` (both optional, no HTTP-to-HTTPS redirect unless `r` is added); 50 worker threads; reverse-proxy `prefix` setting. Sources: [config.c L1084-L1098](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1084-L1098), [config.c L1173-L1180](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1173-L1180)
- REST API at `/api`: OpenAPI 3.0.2 spec (`info.version` "6.0", 74 paths) embedded in FTL and served at `/api/docs`; also published online per branch. Sources: [main.yaml L1-L16](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L1-L16), [main.yaml L72-L291](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L72-L291), [docs: API](https://docs.pi-hole.net/api/#accessing-the-api-documentation)
- API areas: auth, stats, history, queries, DNS blocking, domains, groups, clients, lists, info, logs, config (`/config/{element}/{value}`), network, Teleporter, actions (gravity, restartdns, flush logs/network), DHCP leases, search, PADD. Source: [main.yaml L72-L291](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L72-L291)
- API sessions: `POST /api/auth` returns a session ID (SID) and a CSRF token; the SID is passed as a query parameter, in the body, in `X-FTL-SID`, or as a cookie (cookies need `X-FTL-CSRF`). The docs state there are no static API tokens. Source: [docs: API auth](https://docs.pi-hole.net/api/auth/#use-the-sid-to-access-api-endpoints)
- App password: a single application password usable instead of password+TOTP; `webserver.api.app_sudo` (default false) decides whether it may change config. Sources: [config.c L1242-L1254](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1242-L1254), [docs: API auth](https://docs.pi-hole.net/api/auth/)
- TOTP 2FA: `webserver.api.totp_secret` turns on TOTP for API and UI; `/api/auth/totp` generates a secret. Sources: [config.c L1234-L1240](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1234-L1240), [docs: 2FA](https://docs.pi-hole.net/api/auth/#authentication-with-2fa)
- CLI password: `webserver.api.cli_pw` (default true) writes a per-start password readable by the `pihole` CLI; such sessions cannot change config. Source: [config.c L1256-L1261](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1256-L1261)
- `pihole` CLI: allow, deny, `--regex`, `--wild`, `--allow-regex`, `--allow-wild`, debug, flush, repair, tail, `api <endpoint>`, setpassword, updateGravity, logging, query, updatePihole, version, uninstall, status, enable/disable (with timer), reloaddns, reloadlists, checkout, networkflush. Sources: [pihole L477-L530](https://github.com/pi-hole/pi-hole/blob/v6.4.3/pihole#L477-L530), [docs: pihole command](https://docs.pi-hole.net/main/pihole-command/)
- `pihole-FTL` CLI: `--config key [value]` (and `-t` to test a value), `--teleporter [file]`, `regex-test`, `sqlite3`, `sqlite3_rsync`, `dnsmasq-test`, `ptr`, `dhcp-discover`, `arp-scan`, `--totp`, `--perf`, `--gen-x509`, `verify`, `lua`, `-- <dnsmasq options>`. Sources: [args.c L1200-L1376](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L1200-L1376), [args.c L416-L420](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L416-L420), [args.c L490-L498](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L490-L498)
- Config file: `/etc/pihole/pihole.toml`, 167 keys in v6.7.1 (sections dns, dhcp, ntp, resolver, database, webserver, files, misc, debug); editable via file, CLI, API or UI. Sources: [docs: configuration](https://docs.pi-hole.net/ftldns/configfile/), [config.c L423-L1690](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1690), [test/pihole.toml L1774](https://github.com/pi-hole/FTL/blob/v6.7.1/test/pihole.toml#L1774)
- Environment variables: `FTLCONF_<section>_<key>` (arrays separated by `;`); any key set this way becomes read-only and reverts to its default when unset. Docker also takes `WEBPASSWORD_FILE` for secrets. Sources: [docs: Docker env](https://docs.pi-hole.net/docker/configuration/#configuring-ftl-via-the-environment), [docs: web password](https://docs.pi-hole.net/docker/configuration/#setting-the-web-interface-password)
- `misc.readOnly` locks the config against API/CLI changes "when a configuration is to be forced ... by infrastructure-as-code providers". There is no Terraform provider in the pi-hole GitHub organisation. Sources: [config.c L1455-L1460](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1455-L1460), [pi-hole org repositories](https://github.com/orgs/pi-hole/repositories)
- Teleporter: ZIP export/import via UI, API (`/api/teleporter`) and CLI. It contains `pihole.toml`, `/etc/hosts`, `dhcp.leases`, the gravity tables (group, adlist, adlist_by_group, domainlist, domainlist_by_group, client, client_by_group) and FTL tables (message, aliasclient, network, network_addresses). Import is selective per table and accepts v5 `.tar.gz` archives. Sources: [teleporter.c L47-L64](https://github.com/pi-hole/FTL/blob/v6.7.1/src/zip/teleporter.c#L47-L64), [L174-L260](https://github.com/pi-hole/FTL/blob/v6.7.1/src/zip/teleporter.c#L174-L260), [teleporter.yaml L1-L90](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/teleporter.yaml#L1-L90), [api/teleporter.c L336-L346](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/teleporter.c#L336-L346)
- Teleporter archives are not password-protected or encrypted in the release; a PR to add a password is open. Source: [FTL PR #3227](https://github.com/pi-hole/FTL/pull/3227)
- Official integrations: PADD (terminal dashboard, `pi-hole/PADD`, v4.1.0 on 2025-10-27) and a Home Assistant guide using the REST API. Sources: [PADD README](https://github.com/pi-hole/PADD), [docs: Home Assistant](https://docs.pi-hole.net/guides/misc/homeassistant/), [padd.yaml](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/padd.yaml)
- Prometheus: no official exporter or `/metrics` endpoint; `/api/info/metrics` returns JSON DNS/DHCP metrics. The docs link a community exporter (`nlamirault/pihole_exporter`); 2017/2018 Discourse requests for an exporter got no implementation. Sources: [info.yaml L269-L288](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/info.yaml#L269-L288), [docs: community projects](https://docs.pi-hole.net/main/projects/), [Discourse: Prometheus export](https://discourse.pi-hole.net/t/feature-optionally-export-metrics-for-prometheus/2242), [Discourse: exporter](https://discourse.pi-hole.net/t/feature-exporter-to-prometheus/12322)
- Remote syslog: not supported (open request since 2017). Source: [Discourse: remote logserver](https://discourse.pi-hole.net/t/request-option-to-send-logs-to-a-remote-logserver/1381)
- Legacy telnet API (port 4711): gone in v6. Neither the docs nor the OpenAPI spec mention it; the only remnant in FTL v6.7.1 is an unreferenced `enum telnet_type`. Sources: [enums.h L258-L262](https://github.com/pi-hole/FTL/blob/v6.7.1/src/enums.h#L258-L262), [main.yaml L72-L291](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L72-L291)
- Extra built-in services: an NTP server (IPv4/IPv6, on by default) and an NTP client that sets system time from `pool.ntp.org` (on by default). Sources: [config.c L882-L959](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L882-L959), [docs: NTP](https://docs.pi-hole.net/guides/misc/ntp/)

### 9. High availability, clustering, config sync

- Nothing is built in: none of the 167 config keys covers clustering, peer sync, VRRP or failover, and the docs repository does not mention keepalived, VRRP, nebula-sync or gravity-sync. Sources: [config.c L423-L1690](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1690), [docs repository at ea18203](https://github.com/pi-hole/docs/tree/ea18203eabe718bcb0ea6c7684d20623e3d5639e)
- Official position: "There are no plans to include any high-availability features from our side. But as always, we're up for external contributions." (staff, 2023-10-07). In 2024 staff said the v6 API's remote Teleporter upload/download "could simplify a high availability setup dramatically". Sources: [Discourse HA #107](https://discourse.pi-hole.net/t/high-availability-ha-for-pi-hole-running-two-pi-holes/3138/107), [Discourse HA #108](https://discourse.pi-hole.net/t/high-availability-ha-for-pi-hole-running-two-pi-holes/3138/108)
- The HA feature request is the most-voted request on the forum (193 votes, open since 2017-05-14). Staff estimated it at "50-100 hours at least" and asked for sponsorship (2022). Sources: [Discourse: HA request](https://discourse.pi-hole.net/t/high-availability-ha-for-pi-hole-running-two-pi-holes/3138), [Discourse HA #93](https://discourse.pi-hole.net/t/high-availability-ha-for-pi-hole-running-two-pi-holes/3138/93), [Discourse feature requests by votes](https://discourse.pi-hole.net/c/feature-requests/8/l/top?order=votes&period=all)
- Third-party sync, not by Pi-hole: nebula-sync (`lovelaze/nebula-sync`, for v6, active), gravity-sync (`vmstan/gravity-sync`, v5 only, archived), orbital-sync (`mattwebbio/orbital-sync`, archived). Sources: [nebula-sync](https://github.com/lovelaze/nebula-sync), [gravity-sync](https://github.com/vmstan/gravity-sync), [orbital-sync](https://github.com/mattwebbio/orbital-sync)
- Third-party HA: "Pi-hole HA" (`RamSet/pihole-ha-cluster`, Apache-2.0, created 2026-07-05) adds DHCP failover, a floating VIP and config sync. It is a personal repository announced by a forum moderator in "Customizing Pi-hole", not part of the pi-hole organisation. Sources: [Discourse: Pi-hole HA release](https://discourse.pi-hole.net/t/release-pi-hole-ha-automatic-dhcp-failover-vip-and-config-sync-for-a-pi-hole-cluster/86667), [RamSet/pihole-ha-cluster](https://github.com/RamSet/pihole-ha-cluster), [pi-hole org repositories](https://github.com/orgs/pi-hole/repositories)
- Building blocks the official tools do provide: Teleporter via API, `GET/PATCH /api/config`, `FTLCONF_` env vars, `misc.readOnly`, and `pihole-FTL sqlite3_rsync`. Each node keeps its own query database and statistics. Sources: [main.yaml L234-L262](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/docs/content/specs/main.yaml#L234-L262), [config.c L1455-L1460](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1455-L1460), [args.c L1256-L1257](https://github.com/pi-hole/FTL/blob/v6.7.1/src/args.c#L1256-L1257)

### 10. Security

- Process user: systemd runs `pihole-FTL` as user `pihole` with ambient capabilities `CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_NICE CAP_IPC_LOCK CAP_CHOWN CAP_SYS_TIME`, `ProtectSystem=full` and `ReadWriteDirectories=/etc/pihole`; a prestart script runs as root. Source: [pihole-FTL.systemd L18-L38](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole-FTL.systemd#L18-L38)
- No further sandboxing: the unit sets no `NoNewPrivileges`, and neither the release nor `development` sources contain seccomp or Landlock code. Sources: [pihole-FTL.systemd](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole-FTL.systemd), [FTL v6.7.1 src](https://github.com/pi-hole/FTL/tree/v6.7.1/src), [FTL development src](https://github.com/pi-hole/FTL/tree/91fadcf795325edef55a3e9097778b1c45e266cb/src)
- Docker: FTL expects `NET_BIND_SERVICE`, `NET_RAW`, `NET_ADMIN`, `SYS_NICE`, `CHOWN` and `SYS_TIME`; the image grants them to the non-root process. `DNSMASQ_USER=root` is an option for some NAS systems. Sources: [docs: Docker capabilities](https://docs.pi-hole.net/docker/configuration/#note-on-capabilities), [docs: Docker advanced variables](https://docs.pi-hole.net/docker/configuration/#advanced-variables)
- Web TLS: on first start FTL generates its own CA plus a server certificate (EC by default) for `webserver.domain`; validity 47 days (minimum 7), auto-renewed 2 days before expiry; the CA key is discarded. Custom PEM certificates go in `webserver.tls.cert`. Sources: [docs: TLS](https://docs.pi-hole.net/api/tls/), [config.c L1128-L1155](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1128-L1155), [x509.c L147-L180](https://github.com/pi-hole/FTL/blob/v6.7.1/src/webserver/x509.c#L147-L180)
- Password storage: Balloon hashing over SHA-256 (s_cost 1024, t_cost 32) with salt; the app password is hashed the same way. Source: [password.c L206-L240](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/password.c#L206-L240)
- Brute-force protection: at most 3 password attempts per second, counted globally (not per IP); excess attempts sleep 250 ms and get HTTP 429. TOTP is limited to one attempt per second. Sources: [password.c L437-L467](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/password.c#L437-L467), [password.h L38](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/password.h#L38), [auth.c L728-L736](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/auth.c#L728-L736), [2fa.c L242-L260](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/2fa.c#L242-L260)
- Sessions: at most 16 concurrent (`max_sessions`, 429 when full), 1800 s idle timeout, restored from the database after restart, bound to client IP, `HttpOnly` cookie and CSRF token. Sources: [config.c L1135-L1146](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1135-L1146), [config.c L1204-L1210](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1204-L1210), [auth.c L715-L726](https://github.com/pi-hole/FTL/blob/v6.7.1/src/api/auth.c#L715-L726), [docs: session security](https://docs.pi-hole.net/api/auth/#security-implications-of-session-based-authentication)
- No password means no authentication on the API. Both the installer and the Docker image set a random password on fresh installs (installer: 8 characters from `[_A-Za-z0-9-]`). Sources: [docs: API auth](https://docs.pi-hole.net/api/auth/), [basic-install.sh L2491-L2504](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L2491-L2504), [docs: Docker env](https://docs.pi-hole.net/docker/configuration/#recommended-environment-variables)
- Exposure defaults: web ACL empty (all clients allowed), web server on all interfaces on 80/443, `allow_destructive` true, DNS `listeningMode=LOCAL`. Default security headers include a CSP, `X-Frame-Options: DENY` and `nosniff`. Sources: [config.c L1076-L1112](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1076-L1112), [config.c L1298-L1303](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1298-L1303)
- 2026 advisories, FTL: 17 published in 2026 (13 high, 3 moderate, 1 low), including RCE through newline injection into generated dnsmasq config, CivetWeb option injection, a session-expiry bypass, an unauthenticated session-hijack race, missing API rate limiting, and a stack overflow in the blocked-answer path. Source: [FTL security advisories](https://github.com/pi-hole/FTL/security/advisories)
- Follow-up hardening in FTL v6.7.1: `misc.dnsmasq_lines` and `webserver.advancedOpts` can no longer be changed via API/UI. Source: [FTL v6.7.1 notes](https://github.com/pi-hole/FTL/releases/tag/v6.7.1)
- 2026 advisories, Core and Web: Core had 3, all local privilege escalation from `pihole` to root. Web had 7 (stored/reflected XSS/HTML injection, plus a critical v5 command injection). Sources: [Core security advisories](https://github.com/pi-hole/pi-hole/security/advisories), [Web security advisories](https://github.com/pi-hole/web/security/advisories)
- 2026 advisories, embedded dnsmasq: six upstream dnsmasq CVEs (heap OOB write, DNSSEC DoS and crash, DHCP helper overflow, ECS validation bypass, OOB read) were imported in FTL v6.6.2. Source: [FTL v6.6.2 notes](https://github.com/pi-hole/FTL/releases/tag/v6.6.2)
- Security process: GitHub private vulnerability reporting or `disclosure@pi-hole.net` (org-wide SECURITY.md); advisories are linked in release notes. Sources: [pi-hole/.github SECURITY.md](https://github.com/pi-hole/.github/blob/master/SECURITY.md), [FTL v6.7 notes](https://github.com/pi-hole/FTL/releases/tag/v6.7)
- Supply chain, binary: the installer downloads `pihole-FTL` and a `.sha1` file from the same location and checks it with `sha1sum`; release assets contain no signatures, SBOM or attestations. Sources: [basic-install.sh L1873-L1890](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L1873-L1890), [FTL v6.7.1 assets](https://github.com/pi-hole/FTL/releases/tag/v6.7.1)
- Supply chain, image and self-check: the Docker build runs with `sign: false`. `pihole-FTL verify` checks a SHA-256 appended to the binary (integrity, not authenticity). Sources: [build-and-publish.yml L86-L87](https://github.com/pi-hole/docker-pi-hole/blob/a4b24e115ee161e9f991f955d030dc8f24257289/.github/workflows/build-and-publish.yml#L86-L87), [files.c L797-L808](https://github.com/pi-hole/FTL/blob/v6.7.1/src/files.c#L797-L808)

### 11. Performance claims or benchmarks

- README/docs claim: "Scalable: capable of handling hundreds of millions of queries when installed on server-grade hardware", linking a 2017 blog post. Sources: [Core README](https://github.com/pi-hole/pi-hole/blob/v6.4.3/README.md), [docs: overview](https://docs.pi-hole.net/)
- Disagreement: the linked post says only that a 4 GB RAM VM "was able to handle well over a million queries in 24 hours", plus anecdotal client counts (e.g. 475 clients on a Raspberry Pi 3B, 400 clients on a 512 MB VM). It gives no methodology. Source: [pi-hole.net blog, 2017-05-24](https://pi-hole.net/2017/05/24/how-much-traffic-can-pi-hole-handle/)
- No benchmark numbers are published in the docs; the benchmarking guide is a do-it-yourself `dig -f` replay of your own query log. Source: [docs: benchmarking](https://docs.pi-hole.net/guides/misc/benchmark/)
- Design claims: regex checks run once per domain and the result is cached; the upstream-selection tweak "greatly reduce[s] the number of actually performed queries". Sources: [docs: regex](https://docs.pi-hole.net/regex/), [docs: DNS resolver](https://docs.pi-hole.net/ftldns/dns-resolver/#improve-detection-algorithm-for-determining-the-best-forward-destination)
- Code-level signals: `gravity-db.c` comments mention "the 1-2 ms tail seen in production" for list lookups, and `debug.performance` reports the share of list lookups slower than 1 ms. Sources: [gravity-db.c L1680-L1684](https://github.com/pi-hole/FTL/blob/v6.7.1/src/database/gravity-db.c#L1680-L1684), [config.c L1683-L1687](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1683-L1687)
- Architecture limits stated in config help: shared memory with forked TCP workers (warning at 90% use), and a warning when the 15-minute load average exceeds the core count. Sources: [config.c L1481-L1501](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1481-L1501)
- Recent releases list performance work (v6.4, v6.5 "Low-memory hardware optimizations", v6.7) without numbers. The unreleased DoH server PR states "DoH now resolves in ~2 ms/query". Sources: [FTL v6.4](https://github.com/pi-hole/FTL/releases/tag/v6.4), [FTL v6.5](https://github.com/pi-hole/FTL/releases/tag/v6.5), [FTL v6.7](https://github.com/pi-hole/FTL/releases/tag/v6.7), [FTL PR #2989](https://github.com/pi-hole/FTL/pull/2989)

### 12. Limitations, long-standing requests, roadmap

- Most-voted open feature requests on the forum (votes as of 2026-10-09):
  - HA (193)
  - running directly on routers (58)
  - ignore domains in the query log (36)
  - FreeBSD (35)
  - "temporarily allow" (30)
  - extra DHCP options (22)
  - wildcard local DNS records (19)
  - timed blocking (13)
  - remote syslog (8)
  - audit log (5)
  - blocking IPs from lists (5)
  - gravity schedule in the GUI (5)

  Sources: [Discourse feature requests by votes](https://discourse.pi-hole.net/c/feature-requests/8/l/top?order=votes&period=all), [HA](https://discourse.pi-hole.net/t/high-availability-ha-for-pi-hole-running-two-pi-holes/3138), [routers](https://discourse.pi-hole.net/t/pihole-directly-on-routers-tomato-merlinwrt-dd-wrt-openwrt/1314), [FreeBSD](https://discourse.pi-hole.net/t/freebsd-compatability/2092), [audit log](https://discourse.pi-hole.net/t/audit-log/2058), [block IPs](https://discourse.pi-hole.net/t/pihole-ftl-block-ips-from-lists/21319)
- Closed long-standing requests now addressed: multiple conditional-forwarding entries (now the `dns.revServers` array); DoT (closed; native support is on `development`, see section 5). Sources: [Discourse: conditional forwarding](https://discourse.pi-hole.net/t/more-than-one-conditional-forwarding-entry-in-the-gui/11359), [Discourse: DoT](https://discourse.pi-hole.net/t/implement-dns-over-tls-capability-in-pi-hole/8722/79)
- Structural limitations visible in the release:
  - Linux only
  - no built-in HA or sync
  - no encrypted DNS in or out
  - no recursion
  - global-only upstreams, blocking mode and local records (no per-group policy beyond lists and regex)
  - no safe search, blocked services or schedules
  - only a global blocking toggle
  - ABP support limited to `||domain^`
  - no audit log of config changes (only `debug.api` request logging)

  Sources: sections 1-9 above, [config.c L1557-L1561 (debug.api)](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1557-L1561)
- Operational limitation: changing many common settings (including upstreams, CNAME records, conditional forwarding, cache size and any DHCP setting) restarts FTL. Source: [config.c (FLAG_RESTART_FTL)](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L423-L1451)
- Public roadmap: none found. No roadmap page exists in the docs or READMEs (GitHub Projects could not be checked). The closest statements are DL6ER's plan on Discourse (DoT/DoH client, then OpenSSL, then HTTP/2, then DoT/DoH server, then DoQ; "no promised release date yet") and the v6.7.2 draft calling OpenSSL, DoT/DoH and the TLS terminator "the v7 work". Sources: [Discourse: DoT (staff)](https://discourse.pi-hole.net/t/implement-dns-over-tls-capability-in-pi-hole/8722/79), [Discourse: built-in DoH (staff)](https://discourse.pi-hole.net/t/built-in-support-of-dns-over-https-doh/50658), [FTL PR #3206](https://github.com/pi-hole/FTL/pull/3206)
- `development` activity: 617 commits ahead of `master` and 183 PRs merged into it since v6.7 (2026-07-06), including the encrypted-DNS work, removal of `dns.blockESNI` and `ntp.sync.rtc.set` enabled by default. Sources: [compare master...development](https://github.com/pi-hole/FTL/compare/master...development), [FTL PR #3023](https://github.com/pi-hole/FTL/pull/3023), [FTL PR #3108](https://github.com/pi-hole/FTL/pull/3108)

#### Source disagreements found

- Blocking mode value: docs say `NXDOMAIN`, the parser accepts only `NX`. Sources: [docs](https://docs.pi-hole.net/ftldns/blockingmode/#pi-holes-nxdomain-blocking-mode), [datastructure.c L987-L1001](https://github.com/pi-hole/FTL/blob/v6.7.1/src/datastructure.c#L987-L1001)
- `database.maxDBdays` default: docs say 365, code says 91. Sources: [query-database.md L8](https://github.com/pi-hole/docs/blob/ea18203eabe718bcb0ea6c7684d20623e3d5639e/docs/database/query-database.md?plain=1#L8), [config.c L1009-L1018](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1009-L1018)
- Privacy level restart: docs say no restart is needed, the config help says a restart happens, and the key has no restart flag. Sources: [docs](https://docs.pi-hole.net/ftldns/privacylevels/), [config.c L1396-L1410](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/config.c#L1396-L1410)
- Throughput claim: README says "hundreds of millions of queries", the linked post says "well over a million queries in 24 hours". Sources: [README](https://github.com/pi-hole/pi-hole/blob/v6.4.3/README.md), [blog](https://pi-hole.net/2017/05/24/how-much-traffic-can-pi-hole-handle/)
- Local DNS list path: FAQ says `/etc/pihole/custom.list`, v6 code writes `/etc/pihole/hosts/custom.list`. Sources: [FAQ](https://docs.pi-hole.net/main/faq/#in-which-order-are-locally-defined-dns-records-used), [dnsmasq_config.h L36-L39](https://github.com/pi-hole/FTL/blob/v6.7.1/src/config/dnsmasq_config.h#L36-L39)
- Init systems: prerequisites name systemd and sysvinit; Core also supports OpenRC. Sources: [prerequisites](https://docs.pi-hole.net/main/prerequisites/#software), [pihole-FTL.openrc](https://github.com/pi-hole/pi-hole/blob/v6.4.3/advanced/Templates/pihole-FTL.openrc)
- Installer DNS presets: docs say "nine options" and "7 preset providers"; the installer has 8 presets plus Custom. Sources: [docs](https://docs.pi-hole.net/guides/dns/upstream-dns-providers/), [basic-install.sh L45-L56](https://github.com/pi-hole/pi-hole/blob/v6.4.3/automated%20install/basic-install.sh#L45-L56)

## Numa

As of 2026-10-09, Numa v0.24.1 (2026-10-03); source read at commit `1ea94f89` (2026-10-09).

Method: shallow clone of `main` at commit `1ea94f89ba63aafcc69cb34166b5bed3c60ad618`, GitHub release notes (`gh release view`), repository and commit metadata (`gh repo view`, GitHub REST API), open issues (`gh issue list`), and the project website (numa.rs, whose source is `site/index.html` in the repo). Code links point at that commit. "Not found" means a search of `src/`, `README.md`, `numa.toml`, `recipes/` and `site/dashboard.html` for the relevant terms returned nothing; the search terms are given. Points marked **inference** come from reading code and were not run against a live Numa.

### 1. What Numa is, stack, licence, status, platforms

- Numa describes itself as "a portable DNS resolver in a single binary": ad blocking on any network, named local services (`frontend.numa`), hostname overrides with auto-revert, and ODoH (RFC 9230) for outbound queries, "all from your laptop, no cloud account or Raspberry Pi required". ([README L7-L11](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L7-L11))
- Audience: first a single machine (laptop or developer workstation), then optionally a small network ("Hub mode"). The maintainer writes that "numa is built for LAN, tailnet and personal use" and should not yet be called a turnkey public resolver. ([README L145-L147](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L145-L147), [issue #378](https://github.com/razvandimescu/numa/issues/378))
- Language and layout: Rust, edition 2021, one crate (library plus binary), no workspace. No MSRV is pinned: `Cargo.toml` has no `rust-version` and there is no root `rust-toolchain.toml`. ([Cargo.toml L1-L10](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L1-L10), [src/lib.rs L1-L58](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lib.rs#L1-L58))
- No DNS library: the wire format is hand-written. The README says the parser was written by hand as a learning project and that "later features (recursive resolver, DNSSEC, dashboard) were built with AI assistance". `hickory-*` crates appear only as dev-dependencies, and the shipped binary does not link them. ([README L11](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L11), [Cargo.toml L52-L58](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L52-L58), [.cargo/audit.toml L5-L11](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.cargo/audit.toml#L5-L11))
- Key runtime dependencies:
  - tokio, axum 0.8, hyper 1 and reqwest 0.13 (rustls, HTTP/2)
  - rustls 0.23 and tokio-rustls, with ring as the only crypto provider
  - ring (DNSSEC) and rcgen (local CA)
  - odoh-rs and psl (ODoH)
  - socket2, and quinn-udp for UDP socket state only (not QUIC)
  - arc-swap, serde and toml, log and env_logger
  - qrcode, ipnet, proxy-header, webpki-root-certs
  - windows-service, on Windows only

  Errors use a `Box<dyn Error>` alias. ([Cargo.toml L12-L50](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L12-L50), [src/lib.rs L57-L58](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lib.rs#L57-L58))
- Licence: MIT. ([LICENSE](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/LICENSE), [Cargo.toml L7](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L7))
- Release status: pre-1.0. The latest release is v0.24.1 (2026-10-03). There have been 38 GitHub releases since v0.2.0 (2026-03-21), and 0.24.1 is also on crates.io. ([v0.24.1 release](https://github.com/razvandimescu/numa/releases/tag/v0.24.1), [releases](https://github.com/razvandimescu/numa/releases), [crates.io API](https://crates.io/api/v1/crates/numa))
- Activity:
  - The repository was created on 2020-12-29 with a README-only commit. Real development starts in March 2026.
  - There are 729 commits on `main`. Commits per month in 2026: Mar 114, Apr 278, May 152, Jun 67, Jul 23, Aug 33, Sep 45, Oct 1–9 15.
  - It is effectively a single-maintainer project: `razvandimescu` has 674 commits, Dependabot 38, and the next contributor 3.
  - Repository counts: 1,529 stars, 106 forks, 29 open issues and PRs (21 of them issues). The last push was on 2026-10-09.

  ([first commit](https://github.com/razvandimescu/numa/commit/c4306f446dcfb9c90cf2991f8c6ac7c88a71efdf), [commits API](https://api.github.com/repos/razvandimescu/numa/commits), [contributors API](https://api.github.com/repos/razvandimescu/numa/contributors), [repository](https://github.com/razvandimescu/numa))
- Platforms: macOS, Linux and Windows are supported for service install and system-DNS takeover. Release binaries are built for:
  - Linux x86_64 and aarch64 (musl)
  - Linux armv6 (Pi Zero W)
  - macOS x86_64 and aarch64
  - Windows x86_64

  FreeBSD is only cross-built in CI, and `numa install` refuses on other operating systems. ([release.yml L16-L33](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/release.yml#L16-L33), [ci.yml L97-L107](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/ci.yml#L97-L107), [system_dns.rs L1180-L1204](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L1180-L1204))
- Install methods:
  - Homebrew tap
  - `curl … install.sh | sh`
  - `pacman -S numa`, with an AUR publish workflow
  - `cargo install numa`
  - Nix flake
  - Docker `ghcr.io/razvandimescu/numa` (linux/amd64 and linux/arm64)
  - Windows zip from Releases

  ([README L32-L50](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L32-L50), [README L149-L171](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L149-L171), [docker.yml L54-L70](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/docker.yml#L54-L70), [publish-aur.yml](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/publish-aur.yml), [flake.nix](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/flake.nix))
- `install.sh` downloads the latest release tarball into `/usr/local/bin` and does not check the published `.sha256` file. ([install.sh L37-L61](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/install.sh#L37-L61))
- `numa install` does three things, and `uninstall` reverses them. `--no-system-dns` skips the DNS step.
  - It registers a service: launchd, systemd, or the Windows SCM.
  - It points system DNS at Numa: on Windows it binds `127.0.0.2:53` behind an NRPT rule, and on Linux it adds a systemd-resolved drop-in.
  - It trusts the local CA.

  ([README L58-L70](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L58-L70), [system_dns.rs L1187-L1229](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L1187-L1229))

### 2. Filtering and ad blocking

- Default: blocking is on, with one list, HaGeZi Pro (`wildcard/pro-onlydomains.txt` on raw.githubusercontent.com). Lists refresh every 24 h (`refresh_hours`, minimum 1). A refresh that loads nothing is retried sooner. ([config.rs L622-L641](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L622-L641), [serve.rs L304-L328](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L304-L328))
- Sources can be `http(s)://` URLs, `file://` URLs or bare absolute paths. Duplicate sources are dropped. ([numa.toml L126-L143](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L126-L143), [blocklist.rs L360-L367](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L360-L367))
- List formats and rule syntax: one parser handles every source.
  - It skips empty lines and lines starting with `#` or `!`.
  - It reads hosts lines starting with `0.0.0.0`, `127.0.0.1` or `::`, including several aliases per line and inline `#` comments.
  - Any other line must be a single token. The parser strips a leading `*.` or `||`, any `$options`, and a trailing `^`.

  ([blocklist.rs L380-L421](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L380-L421))
- Matching: every entry blocks the domain and all of its subdomains, whatever the syntax, so `*.x.com` also blocks `x.com`. An entry must contain a dot. ([numa.toml L133-L134](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L133-L134), [blocklist.rs L450-L479](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L450-L479), [client_policy.rs L191-L200](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/client_policy.rs#L191-L200))
- Not supported (searched for `@@`, `regex`, `$important`, `dnsrewrite`):
  - AdGuard/uBlock exception rules (`@@`)
  - regex rules
  - modifiers: they are stripped, not applied
  - exact-only matches
  - `$dnsrewrite`

  **Inference:** a line such as `@@||x.com^` is stored as the literal string `@@||x.com`, which never matches. It neither blocks nor allows. ([blocklist.rs L407-L414](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L407-L414))
- List health:
  - A response is rejected as "not a list" if under half of its entry lines parse.
  - Non-2xx responses are rejected (since 0.23.0).
  - The last good copy of each remote list is kept under `<data_dir>/blocklists`. It is used when a refresh fails and never expires.
  - `/blocking/stats` reports each source's status.

  ([blocklist.rs L423-L448](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L423-L448), [numa.toml L128-L132](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L128-L132), [v0.23.0 notes](https://github.com/razvandimescu/numa/releases/tag/v0.23.0))
- Storage: an in-memory `HashSet<String>`, matched by exact name and then each parent suffix. A new set is built outside the lock and swapped in under a `std::sync::RwLock` write lock. There is no FST or Bloom filter. ([blocklist.rs L9-L17](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L9-L17), [blocklist.rs L175-L179](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L175-L179), [blocklist.rs L454-L469](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L454-L469), [ctx.rs L37-L45](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L37-L45))
- Allow and deny:
  - There is a global `allowlist` in the config.
  - A runtime allowlist and a manual blocklist can be edited from the dashboard or the API. They are saved as JSON files (`blocking-allow.json`, `blocking-block.json`).
  - The allowlist wins over blocks, and allowing a parent domain unblocks its subdomains.
  - `/blocking/check/{domain}` shows which rule matched.

  ([serve.rs L71-L77](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L71-L77), [blocklist.rs L120-L173](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/blocklist.rs#L120-L173), [api.rs L44-L60](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L44-L60))
- Turning blocking off: `PUT /blocking/toggle`, or `POST /blocking/pause` with a number of minutes. `numa block on|off` edits the config file and needs a restart. ([api.rs L45-L47](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L45-L47), [main.rs L112-L134](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/main.rs#L112-L134), [main.rs L279-L295](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/main.rs#L279-L295))
- Block response: NOERROR with `0.0.0.0` for A and `::` for AAAA (TTL 60). Other query types get NOERROR with an empty answer. This cannot be configured; issue #400 asks for a SERVFAIL option. ([ctx.rs L448-L458](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L448-L458), [ctx.rs L877-L897](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L877-L897), [issue #400](https://github.com/razvandimescu/numa/issues/400))
- Blocked page: when a browser request for a blocked hostname reaches Numa's port-80/443 proxy (`0.0.0.0` connects to the local host), the proxy serves a "Blocked by Numa" page with a one-line allowlist command. ([proxy.rs L378-L398](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/proxy.rs#L378-L398), [acl.rs L24](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/acl.rs#L24))
- Per-client policy: `[[client_policy]]` rules match clients by CIDR or IP (`from`, `exclude`).
  - Each rule carries inline `block`/`allow` domain lists, in the same syntax, and an optional `filter_aaaa`.
  - The first rule that makes an explicit decision wins. Within one rule, allow wins over block.
  - Loopback clients always bypass the rules.
  - Rules are set in the config file only.
  - There are no groups, no named clients, no per-client list URLs and no per-client upstreams.

  ([client_policy.rs L1-L126](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/client_policy.rs#L1-L126), [numa.toml L145-L161](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L145-L161), [README L183](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L183))
- Not supported: schedules or time-based rules, safe search, a blocked-services catalogue, parental control. Searched for `safesearch`, `safe search`, `schedule`, `blocked_services` and `parental`. None appears among the config sections. ([config.rs L12-L40](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L12-L40))
- CNAME handling: the block check only looks at the queried name. Numa follows a CNAME chain itself only when the answer lacks the requested type, so CNAME targets inside an upstream answer are never checked against the lists. **No CNAME uncloaking found.** ([ctx.rs L289-L371](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L289-L371), [ctx.rs L430-L458](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L430-L458))
- DNS rebinding protection is opt-in (`rebind_protect`).
  - It strips private and special-use addresses from non-local answers: RFC 1918, loopback, link-local, CGNAT/Tailscale, ULA, NAT64 and `0.0.0.0/8`. This includes address hints in HTTPS/SVCB records.
  - Its allowlist is saved to disk.
  - The dashboard tags stripped queries and offers one-click allow.

  ([config.rs L126-L140](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L126-L140), [acl.rs L17-L30](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/acl.rs#L17-L30), [ctx.rs L162-L180](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L162-L180), [v0.21.0 notes](https://github.com/razvandimescu/numa/releases/tag/v0.21.0))
- `filter_aaaa`, global or per client, answers AAAA queries with NODATA and strips `ipv6hint` from SVCB/HTTPS records. ([config.rs L98-L103](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L98-L103))

### 3. DNS resolution

- Modes: `forward` (the default), `recursive`, `auto` and `odoh`. ([config.rs L207-L215](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L207-L215), [README L107-L111](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L107-L111))
  - `forward` with no address uses the detected system resolver: `scutil` on macOS; `resolv.conf`, `resolvectl` or a DHCP lease on Linux; the adapter settings on Windows. If none is found it uses Quad9 DoH (`https://9.9.9.9/dns-query`). ([serve.rs L663-L707](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L663-L707), [serve.rs L35](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L35), [system_dns.rs L154-L176](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L154-L176))
  - `auto` probes the root servers at startup. It runs recursive if they answer and Quad9 DoH otherwise. ([serve.rs L675-L689](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L675-L689))
- Upstream protocols:
  - plain UDP `IP[:port]`
  - `tcp://`
  - DoT as `tls://IP[:port]#name`
  - DoH as `https://…`, over HTTP/2 with reqwest
  - ODoH

  Multiple primaries are allowed, plus a `fallback` list. Every plain-UDP primary automatically gets a TCP twin in the fallback list. ([forward.rs L18-L42](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L18-L42), [forward.rs L150-L182](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L150-L182), [serve.rs L709-L732](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L709-L732), [numa.toml L42-L59](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L42-L59))
- DoQ upstream: not supported. There is no QUIC client; `quinn-udp` is used only for the UDP listener socket. Searched for `quic` and `doq`. ([forward.rs L18-L42](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L18-L42), [udp_listener.rs L9](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/udp_listener.rs#L9))
- DoT upstream details:
  - It verifies against bundled Mozilla roots.
  - Without `#name`, the IP is used as the TLS server name.
  - Each query opens a new TCP and TLS connection: there is no connection reuse or pipelining.

  ([forward.rs L255-L265](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L255-L265), [forward.rs L441-L458](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L441-L458))
- Failover: primaries are ranked by SRTT. When fallbacks exist, a primary with SRTT of 4000 ms or more is skipped; fallbacks are tried after the primaries. ([forward.rs L647-L711](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L647-L711), [srtt.rs L7-L20](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/srtt.rs#L7-L20))
- Request hedging: with `hedge_ms` set (default 0, off), Numa sends a second identical query to the same upstream after the delay. This works for UDP, DoH and DoT and is forced off for ODoH. ([config.rs L227-L238](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L227-L238), [config.rs L531-L537](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L531-L537), [forward.rs L681-L691](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L681-L691))
- The upstream timeout defaults to 5000 ms; the example config shows 3000. ([config.rs L528-L530](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L528-L530), [numa.toml L52](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L52))
- Forward mode sets the DO bit upstream, so cached answers keep their RRSIGs, and strips DNSSEC records for clients that did not set DO. Forward mode does not validate DNSSEC: validation runs only for answers resolved recursively. ([forward.rs L654](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L654), [ctx.rs L772-L784](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L772-L784), [ctx.rs L124-L160](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L124-L160))
- Recursive mode:
  - Starts from 13 root hints, all IPv4 by default.
  - Primes 43 TLDs at startup.
  - Minimises QNAMEs only at the root: it asks the root for the TLD's NS.
  - Checks bailiwick for referrals, glue and DS.
  - Refuses nameservers at private or loopback addresses.
  - Limits each query to 48 upstream packets in total, at most 10 glueless NS lookups per referral, a referral depth of 10 and a CNAME depth of 8.
  - Uses a 400 ms UDP timeout per nameserver and retries over TCP on TC.
  - Switches to TCP-first after 3 consecutive UDP failures.

  ([config.rs L456-L523](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L456-L523), [recursive.rs L19-L32](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/recursive.rs#L19-L32), [recursive.rs L50-L78](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/recursive.rs#L50-L78), [recursive.rs L543-L566](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/recursive.rs#L543-L566), [recursive.rs L848-L905](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/recursive.rs#L848-L905))
- Anti-spoofing:
  - Each outbound UDP query uses a fresh connected socket on an OS-chosen ephemeral port.
  - Transaction IDs come from the OS RNG.
  - A reply is accepted only if both the ID and the question match (RFC 5452).
  - Forward mode sends a new random ID upstream instead of the client's (fixed in 0.23.1).
  - **No 0x20 case randomisation:** names are lowercased when parsed, and no 0x20 code exists.

  ([forward.rs L350-L417](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/forward.rs#L350-L417), [packet.rs L10-L16](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/packet.rs#L10-L16), [buffer.rs L150-L164](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/buffer.rs#L150-L164), [v0.23.1 notes](https://github.com/razvandimescu/numa/releases/tag/v0.23.1))
- DNSSEC:
  - Opt-in: `[dnssec] enabled` or `numa dnssec on`. Applies to recursive mode only.
  - With `strict = true`, a Bogus result becomes SERVFAIL. Otherwise Bogus answers are returned without AD.
  - Supported algorithms: 8, 10, 13, 14, 15. Not supported: RSASHA1 (5, 7) and Ed448 (16).
  - Supported DS digests: SHA-256 and SHA-384, not SHA-1.
  - Covers NSEC and NSEC3 denial proofs.
  - Caps NSEC3 at 150 iterations and allows 128 signature checks per validation (KeyTrap).
  - Pins both root KSK-2017 and KSK-2024.

  ([config.rs L774-L780](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L774-L780), [numa.toml L231-L234](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L231-L234), [dnssec.rs L27-L56](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dnssec.rs#L27-L56), [dnssec.rs L721-L755](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dnssec.rs#L721-L755), [dnssec.rs L917-L929](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dnssec.rs#L917-L929), [dnssec.rs L1265](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dnssec.rs#L1265))
- Cache:
  - Structure: one global `HashMap<name, HashMap<qtype, entry>>` behind a `std::sync::RwLock`, storing raw response bytes. The key is name and type only, so there is no per-client or ECS variant.
  - Defaults: 100,000 entries, minimum TTL 60 s, maximum TTL 86,400 s.
  - Negative answers take their TTL from the SOA (RFC 2308), capped at 1 h. Failures are cached for 5 s.
  - When full, it evicts expired entries first, then the stalest.

  ([cache.rs L46-L98](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/cache.rs#L46-L98), [cache.rs L137-L202](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/cache.rs#L137-L202), [config.rs L539-L570](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L539-L570), [ctx.rs L39-L40](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L39-L40))
- Serve-stale and prefetch:
  - Expired entries are served for up to 1 h past their TTL (RFC 8767), with TTL 1.
  - A background refresh starts when under 10% of the TTL remains, or when a stale entry is served.
  - `[cache] warm` resolves the listed names at startup and keeps them fresh.
  - Identical concurrent misses are coalesced into one upstream query.

  ([cache.rs L100-L135](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/cache.rs#L100-L135), [ctx.rs L537-L559](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L537-L559), [ctx.rs L905-L1004](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L905-L1004), [serve.rs L344-L350](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L344-L350))
- Admission control: `max_concurrent_resolutions` (default 512) caps concurrent cache misses across all transports. Over the cap, UDP queries are dropped and stream transports get SERVFAIL. The 0.23.1 release notes say "`0` disables", but the config parser rejects 0. ([config.rs L113-L120](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L113-L120), [config.rs L184-L205](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L184-L205), [v0.23.1 notes](https://github.com/razvandimescu/numa/releases/tag/v0.23.1))
- Local records: `[[zones]]` entries.
  - Supported types: A, AAAA, CNAME, PTR, NS and MX. TXT and SRV are not supported.
  - Wildcards are allowed in the leftmost label.
  - CNAMEs inside local zones are followed. A name that exists without the requested type gets NODATA.
  - Zones are checked before the cache and upstream.
  - They are set in the config file only; there is no API.
  - Issue #224 asks for zone-file-style local data.

  ([config.rs L1840-L1925](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L1840-L1925), [numa.toml L202-L229](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L202-L229), [ctx.rs L412-L417](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L412-L417), [recipes/local-dns-records.md L1-L22](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/recipes/local-dns-records.md#L1-L22), [issue #224](https://github.com/razvandimescu/numa/issues/224))
- Overrides: set through the REST API and held in memory only, so they are lost on restart.
  - A target that parses as IPv4 gives an A record, IPv6 gives AAAA, and anything else gives a CNAME.
  - The default TTL is 60. An optional `duration_secs` makes the override expire ("auto-revert"). `/overrides/environment` creates many at once.
  - Overrides are checked first, and the stored record is returned for every query type.

  ([override_store.rs L9-L41](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/override_store.rs#L9-L41), [override_store.rs L141-L172](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/override_store.rs#L141-L172), [api.rs L116-L154](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L116-L154), [ctx.rs L395-L399](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L395-L399))
- Conditional forwarding: `[[forwarding]]` maps a suffix to one or more upstreams, over any protocol, with SRTT failover. It takes priority over recursive mode. Numa also discovers rules automatically: from macOS supplemental resolvers (`scutil --dns`) and from Linux `resolv.conf` search domains. ([config.rs L42-L84](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L42-L84), [numa.toml L103-L124](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L103-L124), [ctx.rs L561-L590](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L561-L590), [system_dns.rs L308-L406](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L308-L406))
- Special names:
  - `.localhost` resolves to loopback.
  - `.local`, private reverse zones and `_dns.resolver.arpa` are answered NXDOMAIN locally unless a forwarding rule covers them. This means no DDR advertisement.
  - `ipv4only.arpa` is synthesised.
  - ANY queries get a minimal HINFO (RFC 8482).

  ([ctx.rs L383-L424](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L383-L424), [ctx.rs L837-L872](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L837-L872), [ctx.rs L1031-L1063](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L1031-L1063))
- Message size: the packet buffer is fixed at 4096 bytes. A response that does not fit is truncated (TC) even over TCP or TLS; a TODO notes that 65535 is not supported. UDP replies respect the client's EDNS size. ([buffer.rs L3-L16](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/buffer.rs#L3-L16), [ctx.rs L235-L287](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L235-L287), [tcp.rs L28](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tcp.rs#L28))

### 4. Encrypted DNS serving

- Served to clients: plain UDP and TCP on 53, DoT on 853 (RFC 7858), and DoH (RFC 8484, GET and POST) on the proxy's HTTPS port 443. ([serve.rs L445-L460](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L445-L460), [dot.rs L42-L98](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dot.rs#L42-L98), [proxy.rs L166-L214](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/proxy.rs#L166-L214), [doh.rs L19-L109](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/doh.rs#L19-L109))
- Not served: DoQ, DoH over HTTP/2 or HTTP/3 (the HTTPS listener uses hyper's HTTP/1 server only), DNSCrypt, and an ODoH target. `numa relay` runs an ODoH relay. Searched for `quic`, `doq`, `http2` server builders and `dnscrypt`. ([proxy.rs L199-L213](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/proxy.rs#L199-L213), [Cargo.toml L21](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L21), [main.rs L86-L111](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/main.rs#L86-L111))
- DoT:
  - On by default, bound to `0.0.0.0:853`, with ALPN `dot`.
  - Queries on one connection are handled one at a time.
  - 30 s idle timeout, 512-connection cap, 4096-byte message cap.

  ([config.rs L782-L821](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L782-L821), [dot.rs L16-L18](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/dot.rs#L16-L18), [tcp.rs L23-L28](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tcp.rs#L23-L28), [tcp.rs L200-L282](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tcp.rs#L200-L282))
- DoH:
  - Served only on the HTTPS proxy listener, which binds `127.0.0.1` by default; LAN clients need `[proxy] bind_addr = "0.0.0.0"`.
  - Accepted only when the Host header is a loopback name, the TLD (`numa`) or `numa.numa`.
  - Request bodies are limited to 4096 bytes.
  - The DoH recipe says subdomains of `tld` are accepted, but `is_tld_match` accepts only `tld` and `tld.tld`.

  ([config.rs L717-L719](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L717-L719), [doh.rs L84-L109](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/doh.rs#L84-L109), [recipes/doh-on-lan.md L1-L24](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/recipes/doh-on-lan.md#L1-L24))
- Certificates: a self-signed local CA ("Numa Local CA").
  - The CA is valid for 10 years and has no name constraints. Its key sits in `data_dir` with mode 0600.
  - It issues a 1-year leaf certificate for `*.numa`, each service name, `numa.numa`, `localhost`, `127.0.0.1` and `::1`.
  - The leaf is reissued at startup and whenever services or LAN peers change.
  - Bring-your-own PEM certificates are supported for DoT and the proxy. There is no ACME: renew externally, then restart.

  ([tls.rs L22-L23](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tls.rs#L22-L23), [tls.rs L54-L125](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tls.rs#L54-L125), [tls.rs L226-L335](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tls.rs#L226-L335), [numa.toml L176-L181](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L176-L181), [numa.toml L236-L242](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L236-L242))
- Phone onboarding:
  - `numa setup-phone` prints a QR code pointing at `http://<lan-ip>:8765/mobileconfig`.
  - The mobile API on that port is GET-only: `/health`, `/ca.pem`, `/mobileconfig` and `/ca.mobileconfig`.
  - The iOS profile installs the Numa CA as a trusted root and turns on DoT to the LAN IP with SNI `numa.numa`, on Wi-Fi.
  - The profile is unsigned: no signing code was found in `mobileconfig.rs`, although the DoH recipe calls it a "signed profile".

  ([setup_phone.rs L1-L35](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/setup_phone.rs#L1-L35), [mobile_api.rs L1-L55](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/mobile_api.rs#L1-L55), [mobileconfig.rs L125-L185](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/mobileconfig.rs#L125-L185), [recipes/doh-on-lan.md L37](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/recipes/doh-on-lan.md#L37))
- ODoH client: `[upstream] mode = "odoh"` with a relay URL and a target URL.
  - It refuses a relay and target that share a registrable domain (checked with `psl`).
  - With `strict` on (the default), it never falls back to non-oblivious upstreams.
  - `relay_ip` and `target_ip` avoid a bootstrap DNS leak when Numa is its own resolver.

  ([numa.toml L61-L75](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L61-L75), [config.rs L345-L411](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L345-L411), [README L122](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L122))
- PROXY protocol v2 is accepted inbound on UDP, TCP, DoT and the HTTPS proxy. Setting `from` makes the header required on that listener. ([config.rs L682-L715](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L682-L715), [numa.toml L183-L190](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L183-L190))
- Client ACL: `allow_from` applies to every DNS surface (silent drop on UDP, close before the TLS handshake, 403 on DoH). An empty list allows everyone; loopback is always allowed. ([acl.rs L85-L106](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/acl.rs#L85-L106), [numa.toml L26-L31](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L26-L31))

### 5. Developer features (`.numa`, mDNS, local HTTPS)

- `.numa` services map a name to `[target_host:]port`.
  - They are registered with `POST /services`, from the dashboard, or with `[[services]]` in the config.
  - Services added at runtime are saved to `services.json` in the config directory.
  - Names are 1–63 characters, letters, digits and hyphens.

  ([README L90-L101](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L90-L101), [service_store.rs L1-L208](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/service_store.rs#L1-L208), [api.rs L984-L1015](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L984-L1015), [numa.toml L192-L200](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L192-L200))
- DNS side of `.numa`:
  - `<name>.numa` resolves to 127.0.0.1 / ::1 for loopback clients. Remote clients get this host's outgoing IP toward them.
  - Names learned from LAN peers resolve to the peer's IP.
  - Unknown `.numa` names get NXDOMAIN.
  - The TLD is configurable (`[proxy] tld`).
  - On macOS, `/etc/resolver/numa` keeps `.numa` pointed at Numa while a VPN is up.

  ([ctx.rs L473-L520](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L473-L520), [config.rs L730-L732](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L730-L732), [system_dns.rs L1048-L1102](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L1048-L1102))
- Reverse proxy:
  - Listens for HTTP on :80 and HTTPS on :443, on 127.0.0.1 by default.
  - Routes by Host header to `http://<target_host or localhost>:<port>`. Backends must be plain HTTP.
  - Path routes use longest-prefix match, with optional prefix stripping (for example `app.numa/api` → `:5001`).
  - Passes WebSocket/Upgrade connections through, for HMR.
  - Sets `x-numa-client-ip` on forwarded requests.
  - Limits: 128 proxied connections, 30 s header read timeout.

  ([proxy.rs L27-L30](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/proxy.rs#L27-L30), [proxy.rs L366-L545](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/proxy.rs#L366-L545), [service_store.rs L17-L56](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/service_store.rs#L17-L56))
- Local HTTPS: `numa install` adds the local CA to the OS trust store: the macOS keychain via `security add-trusted-cert`, the Linux distribution stores, and the Windows Root store via `certutil`. That gives a valid lock icon for `https://<name>.numa`. Firefox's own NSS store is not handled. ([system_dns.rs L1933-L2094](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L1933-L2094), [README L115-L118](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L115-L118))
- The dashboard is reachable at `http://numa.numa`: the `numa` service is registered automatically and points at the API port. ([serve.rs L87-L98](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L87-L98), [README L66](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L66))
- LAN discovery is off by default (`[lan] enabled`, or `numa lan on`).
  - Every 30 s each instance multicasts an mDNS announcement for `_numa._tcp.local` (PTR, SRV, TXT and A). The TXT record carries the instance's service list, version, API and DoT ports, and CA fingerprint.
  - Other instances make those services resolvable and proxied as `<name>.numa`. Entries expire after 90 s.
  - This is discovery between Numa instances only. Numa does not resolve arbitrary `.local` names over mDNS; it answers them NXDOMAIN.

  ([lan.rs L15-L32](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lan.rs#L15-L32), [lan.rs L144-L252](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lan.rs#L144-L252), [config.rs L744-L772](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L744-L772), [ctx.rs L870-L871](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L870-L871), [README L132-L145](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L132-L145))
- Other developer features: overrides with auto-revert (section 3) and `GET /diagnose/{domain}`. Open issue #200 notes that diagnose is a parallel simulator, not the real resolution path. ([api.rs L37](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L37), [issue #200](https://github.com/razvandimescu/numa/issues/200))
- Companion apps: the code refers to iOS/Android companion apps (`Discovery.swift`, NWBrowser browsing `_numa._tcp.local`). No app is in this repository or linked from the README or site, so whether one has been released is not verified. ([mobile_api.rs L1-L23](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/mobile_api.rs#L1-L23), [lan.rs L192-L199](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lan.rs#L192-L199), [numa.toml L263-L266](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L263-L266))

### 6. Query log, statistics, dashboard, API, CLI, config

- Query log:
  - An in-memory ring of the last 1,000 queries: client, name, type, path, transport, rcode, latency, DNSSEC status, a rebind flag and a sequence number.
  - Filterable through `GET /query-log`.
  - Nothing is saved to disk. Long-term history is left to the separate `numa-metrics` project.

  ([query_log.rs L10-L49](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/query_log.rs#L10-L49), [serve.rs L188](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L188), [api.rs L519-L525](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L519-L525), [README L218](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L218), [numa-metrics](https://github.com/razvandimescu/numa-metrics))
- Every query is also written to the process log at `info` level (client, type, name, path, rcode, ms), and `info` is the default level. As a result, journald on Linux and `/usr/local/var/log/numa.log` on macOS keep a per-query record. ([ctx.rs L189-L197](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L189-L197), [main.rs L31-L33](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/main.rs#L31-L33), [com.numa.dns.plist L15-L22](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/com.numa.dns.plist#L15-L22))
- Stats: `GET /stats` returns counters since start, not time series. They cover:
  - queries per path, transport and upstream transport
  - cache, overrides and blocking
  - LAN discovery, memory, and admission control

  There is no Prometheus or OpenMetrics endpoint; searched for `prometheus`, `/metrics` and `openmetrics`. ([api.rs L185-L224](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L185-L224), [stats.rs L189-L203](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/stats.rs#L189-L203))
- Dashboard: one embedded HTML page with self-hosted fonts that polls the API. It shows:
  - totals and the cache hit rate
  - the last 200 queries, with one-click block or allow
  - overrides, cache and services
  - blocking controls: pause for 5 minutes, allowlist and blocklist, check a name
  - memory, resolution paths and wire protocols
  - a phone-setup QR code

  It has a light/dark theme and JSON locales (en, de, zh-cn, ru). Most settings cannot be changed from the UI; issue #384 asks for that. ([api.rs L19-L30](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L19-L30), [site/dashboard.html L1330-L1360](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/site/dashboard.html#L1330-L1360), [site/locales/manifest.json](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/site/locales/manifest.json), [README L204](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L204), [issue #384](https://github.com/razvandimescu/numa/issues/384))
- REST API: unversioned JSON routes on :5380. They cover:
  - overrides and diagnose
  - query-log and stats
  - cache list and flush
  - health
  - blocking: stats, toggle, pause, allowlist, blocklist, check
  - rebind: status, toggle, allowlist
  - services and their routes
  - `ca.pem`, `qr`, and static assets

  There is no OpenAPI spec (searched for `openapi`, `utoipa`, `swagger`). The README points at `src/api.rs` as the API reference. ([api.rs L28-L99](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api.rs#L28-L99), [README L217](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L217))
- CLI: arguments are parsed by hand (no clap). Commands:
  - `run` (the default)
  - `install [--no-system-dns]`, `uninstall`
  - `service start|stop|restart|status`
  - `config path|edit`
  - `token`
  - `lan|block|dnssec on|off`: these edit the config and need a restart
  - `relay [PORT] [BIND]`
  - `setup-phone`, `version`, `help`

  There is no TUI. ([main.rs L37-L205](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/main.rs#L37-L205))
- Config: one TOML file (`numa.toml`).
  - On Linux and macOS, `numa install` writes the annotated example into the data directory.
  - Sections: `server`, `upstream`, `cache`, `blocking`, `zones`, `proxy`, `services`, `lan`, `dnssec`, `dot`, `mobile`, `forwarding`, `client_policy`.
  - There is no hot reload (restart needed) and no include files (issue #303).
  - State changed at runtime is kept in JSON files in the data and config directories.

  ([config.rs L12-L40](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L12-L40), [system_dns.rs L9-L25](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L9-L25), [README L216](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L216), [issue #303](https://github.com/razvandimescu/numa/issues/303))

### 7. High availability, clustering, config sync

- **Not supported.** The README says "No DHCP, no clustering, no config sync between instances." There is no consensus, replication or VRRP code: a search of `src/` for `cluster`, `raft`, `vrrp`, `keepalived` and `replica` finds nothing. ([README L204](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L204), [src/lib.rs L1-L52](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lib.rs#L1-L52))
- Failure behaviour: if Numa is the only resolver, DNS fails until launchd or systemd restarts it. Serve-stale only covers names already in the cache. ([README L194-L198](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L194-L198))
- Restarts and upgrades: SIGTERM and SIGINT exit cleanly. There is no socket handoff or zero-downtime restart. An upgrade means replacing the binary and re-running `install`, which restarts the service. ([serve.rs L266-L272](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L266-L272), [README L68](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L68))
- Control-plane isolation: DNS keeps serving if the API port is taken; the API retries every 5 s. ([serve.rs L992-L1005](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L992-L1005), [v0.24.0 notes](https://github.com/razvandimescu/numa/releases/tag/v0.24.0))
- LAN discovery shares service names between instances; it does not replicate configuration. ([lan.rs L144-L252](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lan.rs#L144-L252))

### 8. Security

- Privilege model:
  - The Linux systemd unit uses `DynamicUser`, grants only `CAP_NET_BIND_SERVICE`, and sets `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, kernel and cgroup protections, and `RestrictAddressFamilies`.
  - It has no `SystemCallFilter` or `MemoryDenyWriteExecute`; a comment says these may come later.
  - The macOS launchd daemon runs as root.
  - The Docker image has no `USER` line, so it runs as root.
  - The process does not drop privileges itself and uses no seccomp or Landlock; searched for `seccomp`, `landlock`, `setuid` and `chroot`.

  ([numa.service L12-L42](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.service#L12-L42), [README L70](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L70), [Dockerfile L24-L28](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Dockerfile#L24-L28))
- Unsafe code: there is no `#![forbid(unsafe_code)]`. Four places use `unsafe`, all of them foreign-function calls outside the parser:
  - `setsockopt(UDP_GRO)` on Linux
  - mach `task_info` and `sysconf`, for memory statistics
  - `GetProcessMemoryInfo` on Windows

  None has a `// SAFETY:` comment. ([src/lib.rs L1-L58](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/lib.rs#L1-L58), [udp_listener.rs L88-L101](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/udp_listener.rs#L88-L101), [stats.rs L62-L78](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/stats.rs#L62-L78), [stats.rs L102-L104](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/stats.rs#L102-L104))
- Panics:
  - CI runs clippy with `-D warnings`, but the lints that forbid panics (`unwrap_used`, `expect_used`, `indexing_slicing`) are not configured.
  - The parser reads through bounds-checked accessors that return errors, follows at most 5 compression pointers, and uses a fixed 4096-byte buffer.
  - Shared state sits behind std locks taken with `.unwrap()` on the query path.

  ([Cargo.toml L81-L82](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Cargo.toml#L81-L82), [ci.yml L39-L42](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/ci.yml#L39-L42), [buffer.rs L65-L179](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/buffer.rs#L65-L179), [ctx.rs L395-L458](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L395-L458))
- API and dashboard auth:
  - The API is plain HTTP on `127.0.0.1:5380` by default. The Docker image binds it to `0.0.0.0`.
  - Loopback requests need no token when Host is `localhost`, an IP literal or a `.numa` name (a DNS-rebinding guard since 0.24.0).
  - Every other client needs the token: 256 random bits, generated on first start and stored with mode 0600, or set with `api_token` / `NUMA_API_TOKEN`. It is sent as Bearer or Basic and compared in constant time.
  - `/health` is open.
  - No CSRF token or Origin check was found, and the API itself has no TLS. Any local user or process can call the API without a token.

  ([api_auth.rs L1-L185](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/api_auth.rs#L1-L185), [config.rs L162-L164](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L162-L164), [Dockerfile L26](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/Dockerfile#L26), [v0.24.0 notes](https://github.com/razvandimescu/numa/releases/tag/v0.24.0))
- Exposure defaults:
  - DNS binds `0.0.0.0:53` and DoT binds `0.0.0.0:853`, with an empty `allow_from`, which allows everyone. The maintainer documents that this is unsafe on a public IP without `allow_from` or a dnsdist front end.
  - The config template that `numa install` writes on Linux and macOS sets `[mobile] enabled = true`. That opens the read-only mobile API on `0.0.0.0:8765`, although the code default is off and the code comments call it opt-in.

  ([config.rs L171-L176](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L171-L176), [acl.rs L97-L106](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/acl.rs#L97-L106), [issue #378](https://github.com/razvandimescu/numa/issues/378), [numa.toml L257-L266](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/numa.toml#L257-L266), [system_dns.rs L1206-L1221](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/system_dns.rs#L1206-L1221), [config.rs L823-L868](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/config.rs#L823-L868))
- Local CA risk: the CA trusted system-wide, and on phones through the profile, has no name constraints and a 10-year life. Its private key is in `data_dir`, readable by the service. ([tls.rs L22](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tls.rs#L22), [tls.rs L245-L261](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tls.rs#L245-L261))
- Resolver defences: see section 3, plus the opt-in rebinding filter, RFC 8482 ANY handling and the admission cap. TCP and DoT allow 512 connections, a 30 s idle timeout and a 10 s write timeout. Missing, and tracked in issues #378 and #158:
  - response rate limiting
  - DNS cookies
  - per-client rate limits
  - a cap on queries per TCP connection

  ([tcp.rs L23-L28](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/tcp.rs#L23-L28), [issue #378](https://github.com/razvandimescu/numa/issues/378), [issue #158](https://github.com/razvandimescu/numa/issues/158))
- ODoH relay:
  - It keeps no per-request logs.
  - Limits: 4 KiB request body, 8 KiB target response, 5 s timeout.
  - Its hostname check rejects `@` and `/`.

  ([relay.rs L1-L41](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/relay.rs#L1-L41), [relay.rs L202-L215](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/relay.rs#L202-L215))
- Threat model: no threat-model document was found. What exists:
  - `SECURITY.md`: private advisories; in scope are the parser, cache poisoning, DNSSEC bypass, rebinding, control-plane auth/SSRF and the encrypted transports; only the latest release is supported.
  - The README's "Resolver hardening" paragraph.
  - Issue #378, which lists defences in place and the gaps.

  ([SECURITY.md L1-L63](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/SECURITY.md#L1-L63), [README L200-L202](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L200-L202), [issue #378](https://github.com/razvandimescu/numa/issues/378))
- Fuzzing: cargo-fuzz (libFuzzer) with 6 targets: `packet_parse`, `packet_roundtrip`, `svcb_strip`, `dnssec_validate`, `wire_patch` and `serialize_budget`. It uses a committed seed corpus and nightly-2025-12-01, and runs 60 s per target on PRs that touch parser files and 300 s in a weekly cron. ([fuzz.yml L1-L96](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/fuzz.yml#L1-L96), [fuzz/Cargo.toml](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/fuzz/Cargo.toml))
- Tests and CI:
  - Test count: about 761 `#[test]` / `#[tokio::test]` functions, counted with grep over `src/` and `tests/`.
  - CI runs fmt, clippy `-D warnings`, the tests on Linux, macOS and Windows, `cargo audit`, a Nix build, a FreeBSD cross-build, and install/reinstall/uninstall on Linux and macOS. The Linux job also checks the service is not running as root.
  - `tests/integration.sh` and the Docker reproduction scripts are not run by any workflow.
  - There are no property-based tests (no proptest or quickcheck).
  - A daily canary job parses the blocklist URL compiled into the binary.

  ([ci.yml L30-L182](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/ci.yml#L30-L182), [tests/integration.sh L1-L20](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/tests/integration.sh#L1-L20), [blocklist-canary.yml L1-L22](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/blocklist-canary.yml#L1-L22))
- Supply chain:
  - Release artifacts come with SHA-256 files only. No signatures, provenance or SBOM were found in the release workflow.
  - Dependencies are updated by Dependabot. `cargo audit` runs in CI; cargo-deny is not used.

  ([release.yml L60-L120](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/workflows/release.yml#L60-L120), [SECURITY.md L49-L57](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/SECURITY.md#L49-L57), [dependabot.yml](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/.github/dependabot.yml))

### 9. Published performance claims

- README:
  - "0.1ms cached queries — matches Unbound and AdGuard Home"
  - "Wire-level cache stores raw bytes with in-place TTL patching"
  - cold recursive "p99 538ms vs Unbound 748ms (−28%), σ 4× tighter"

  ([README L206-L208](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L206-L208))
- Where those numbers come from, the "fixing DoH tail latency" blog post:
  - Cold recursive method: "unique subdomains, 1 query per domain, 5 iterations, 505 samples per server".
  - Cold recursive results: p99 538 ms vs Unbound 748 ms; σ 114 vs 457 ms; median 77.6 vs 74.7 ms (Unbound has the better median).
  - DoH forwarding method: 5 iterations × 101 domains × 10 rounds.
  - DoH forwarding result (p99): hedged 71.3 ms, single 113.4 ms, Hickory 98.1 ms.
  - Hardware, network and Unbound settings are not stated.

  ([blog/fixing-doh-tail-latency.md L105-L155](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/blog/fixing-doh-tail-latency.md#L105-L155))
- Benchmark harness: `benches/recursive_compare.rs` compares against Hickory, Unbound, AdGuard Home, NextDNS, and DoT/DoH servers. It needs a running Numa with `benches/numa-bench.toml`. ([benches/recursive_compare.rs L1-L17](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/benches/recursive_compare.rs#L1-L17))
- Website numbers:
  - 689 ns cached round trip (parse, cache lookup, serialize)
  - 2.0M QPS, "single-threaded pipeline throughput, batched"
  - "0 allocations — Heap allocations in the I/O path"
  - ECDSA P-256 verify 174 ns, RSA/SHA-256 10.9 µs, DS digest 257 ns
  - about 90 ms for cold-cache DNSSEC validation

  The stated method is "Benchmarked with `dig` against public resolvers on the same machine", reproducible with `cargo bench` and `bench/dns-bench.sh`. Most of these figures are criterion micro-benchmarks, not load tests against the server. ([site/index.html L1499](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/site/index.html#L1499), [site/index.html L1585-L1610](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/site/index.html#L1585-L1610), [bench/README.md L1-L87](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/bench/README.md#L1-L87))
- Committed end-to-end results (`bench/results.json`, 50 `dig` samples each):

  | Target | Average | p99 |
  |---|---|---|
  | Numa, cold cache | 9 ms | 18 ms |
  | Numa, cached | 0 ms (dig rounds to ms) | 0 ms |
  | System resolver | 9.1 ms | 44 ms |
  | Quad9 | 14.5 ms | 43 ms |
  | Cloudflare | 18.7 ms | 132 ms |
  | Google | 22.4 ms | 37 ms |

  ([bench/results.json](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/bench/results.json))
- Claims the code does not support:
  - **"0 allocations":** the code allocates per query. Each UDP query becomes a spawned tokio task. A cache hit clones the stored bytes, parses them into an owned `DnsPacket` (heap Strings and Vecs) and serialises it again. The query name and question are cloned.
  - **Concurrency layout:** the cache is one global RwLock, and each bind address has a single UDP socket, with no `SO_REUSEPORT` fan-out.
  - **No server load test** (dnsperf-style QPS) was published.

  ([serve.rs L465-L512](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/serve.rs#L465-L512), [cache.rs L100-L135](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/cache.rs#L100-L135), [cache.rs L210-L219](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/cache.rs#L210-L219), [ctx.rs L100-L122](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L100-L122), [ctx.rs L537-L559](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/ctx.rs#L537-L559), [udp_listener.rs L20-L34](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/src/udp_listener.rs#L20-L34))
- Binary size: the README says "one ~8MB binary". ([README L11](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L11))

### 10. Limitations, open issues, roadmap

- Limits the project states itself:
  - no DHCP, no clustering, no config sync
  - most settings only in `numa.toml`
  - per-client rules by CIDR, in the config file only
  - a "Dashboard" rather than a full admin UI
  - community maturity "New"

  ([README L173-L192](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L173-L192), [README L204](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L204))
- Limits seen in the code (details and sources in sections 2–6):
  - DNSSEC validation in recursive mode only
  - no CNAME uncloaking
  - adblock syntax reduced to domains
  - no DoQ in either direction; DoH served over HTTP/1.1 only
  - a 4096-byte message ceiling, TCP included
  - queries on one TCP or DoT connection handled one at a time
  - a new DoT upstream connection per query
  - a query log of 1,000 entries held in memory
  - overrides not saved to disk
  - no config reload
- Open issues relevant to goethite's scope:
  - [#378](https://github.com/razvandimescu/numa/issues/378): abuse resistance; RRL with TC-slip, per-client limits, DNS cookies and an end-to-end query deadline are still open
  - [#158](https://github.com/razvandimescu/numa/issues/158): cap on queries per TCP connection
  - [#400](https://github.com/razvandimescu/numa/issues/400): configurable block response
  - [#384](https://github.com/razvandimescu/numa/issues/384): change config from the web UI
  - [#224](https://github.com/razvandimescu/numa/issues/224): richer local records
  - [#303](https://github.com/razvandimescu/numa/issues/303): config includes
  - [#349](https://github.com/razvandimescu/numa/issues/349): no retry without EDNS after FORMERR from a forwarding upstream
  - [#140](https://github.com/razvandimescu/numa/issues/140): several ODoH relays
  - [#93](https://github.com/razvandimescu/numa/issues/93): outgoing-interface binding
  - [#366](https://github.com/razvandimescu/numa/issues/366): LocalRoot
  - [#56](https://github.com/razvandimescu/numa/issues/56): 4 KB buffer zeroed on every allocation
  - [#200](https://github.com/razvandimescu/numa/issues/200): diagnose is a simulator

  ([open issues](https://github.com/razvandimescu/numa/issues))
- Roadmap: the README's unchecked items are "pkarr integration — self-sovereign DNS via Mainline DHT" and "Global `.numa` names — DHT-backed, no registrar". The website adds Phase 14, ".onion bridge — human-readable Tor naming". Nothing on the roadmap concerns HA, multi-user or richer filtering. ([README L220-L237](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/README.md#L220-L237), [site/index.html L1715-L1741](https://github.com/razvandimescu/numa/blob/1ea94f89ba63aafcc69cb34166b5bed3c60ad618/site/index.html#L1715-L1741), [numa.rs](https://numa.rs))
- Places where the documentation and the code disagree:
  1. `max_concurrent_resolutions = 0`: the release notes say "disables", the code rejects it.
  2. Upstream timeout: the example shows 3000 ms, the default is 5000 ms.
  3. The mobile API is described as opt-in, but the installed template enables it.
  4. The DoH Host check is narrower than the recipe says.
  5. The iOS profile is called "signed" but is unsigned.
  6. The website says "0 allocations" in the I/O path.

  (sources in sections 3, 4, 8 and 9)
