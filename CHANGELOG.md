# Changelog

All notable changes to goethite are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and goethite uses
[semantic versioning](https://semver.org/). Before 1.0, minor versions may change the
configuration format.

## [Unreleased]

### Added

- **Blocked answers carry Extended DNS Error 15, "Blocked"** ([RFC
  8914](https://www.rfc-editor.org/rfc/rfc8914)) when the client asked with EDNS, so `dig` and
  browsers can tell a filtered name from a broken one. The info code of an upstream's own EDE is
  relayed unchanged.
- **Safe search for Ecosia, Pixabay and Yandex**, beside Google, YouTube, Bing and DuckDuckGo:
  Ecosia and Pixabay answer with a CNAME to their safe host, and Yandex, which has no such host,
  answers `A` queries with its fixed safe address `213.180.193.56`.
- **A Helm chart**, in `deploy/helm/goethite`: one node on Kubernetes, DNS on port 53 (UDP and
  TCP), the store and the downloaded lists on a PersistentVolumeClaim, and the image's own config
  until you paste a `goethite.toml` into the chart's `config`. By default the pod runs
  unprivileged (65532, no capabilities) with a pod sysctl to bind port 53; `--set
  hostNetwork=true` answers on every node's port 53 instead, with real client addresses. CI lints
  the chart and renders its shapes. See
  [Install on Linux](https://nxplain-sh.github.io/goethite/install/#on-kubernetes-helm).
- **An install script**, served from the site as
  `curl -fsSL https://nxplain-sh.github.io/goethite/install.sh | sh`: it picks the package or the
  tarball for the machine, checks the download against the release's `SHA256SUMS` and installs
  goethite without starting it. The landing page now shows it beside the container and Helm
  options.
- **Check for updates** in the web UI's Settings page, on demand: the node asks GitHub's release
  API (through its own upstreams) for the newest release and says whether it runs it. Nothing is
  installed and nothing is sent on its own; upgrading stays an operator step
  ([Upgrade](https://nxplain-sh.github.io/goethite/install/#upgrade)), and with
  `POST /api/v1/update/check` the same check is available to scripts.
- **Users, roles and sessions for the API and the web UI** (ADR 0039). The admin token stays for
  scripts; people now sign in with a user name and password, and optionally a TOTP second factor
  with one-time recovery codes.
  - `goethite user add|list|passwd|reset|remove|disable|enable` bootstraps the first admin on
    the node (goethite must be stopped; in a cluster, change users through the API).
  - Roles: `admin` (everything) and `viewer` (reads, and its own account).
  - Sessions are `HttpOnly; SameSite=Strict` cookies, twelve hours, and end on every node when
    a user's password, role, second factor or disabled state changes.
  - Password reset is an admin-issued one-time link (`/reset?token=…`, valid an hour); no email
    is sent, so the feature works offline. An admin can also clear a lost second factor.
  - New endpoints under `/api/v1/users` and `/api/v1/auth`, with the OpenAPI document and the
    API reference regenerated. New web UI pages: sign-in with code, Account, Users, Reset.
  - Argon2id password hashes, TOTP secrets and recovery hashes live in the store (replicated,
    schema version 3) and are never written to the audit log or any response.

## [0.6.0] - 2026-10-10

### Added

- **Sending metrics, logs and traces to an OpenTelemetry collector** over OTLP/HTTP, with a new
  `[telemetry]` table: `endpoint`, a `headers_file` for an API key, a `ca_file` for a private CA,
  `metrics`, `logs`, `traces`, `trace_sample_ratio`, `query_details` and `interval`.
  - Nothing is sent without an endpoint, and `/metrics` stays as it was.
  - Log records are the lines at `INFO` and above. They also still go to standard error,
    unchanged.
  - Traces are off by default. With them on, a sampled share (5% by default) of the slow paths
    is traced: queries that missed the cache, with each upstream attempt or each query to an
    authoritative server and DNSSEC validation; list downloads; filter builds; Raft calls; API
    requests. Cache hits, blocks and local answers open no span. Names looked up are on spans
    only with `query_details = true`.
  - goethite sends the requests with its own HTTP client: rustls with ring, names resolved
    through its own upstreams.
  - Exports never touch the DNS path. Failures are counted in
    `goethite_telemetry_export_failures_total` and logged once per outage.

  See [Metrics and telemetry](https://nxplain-sh.github.io/goethite/observability/).

- **A Cluster page in the web UI**, on nodes in a cluster: the cluster's health in a word, the
  voters it can lose, a card per member (up or down, leader, voter, witness, version, how many
  changes behind the leader), how this node follows the leader, and the recovery steps where they
  apply: take the cluster over, join another cluster, remove a member that is down, each after a
  second click. The dashboard's Cluster panel and the header's cluster badges lead to it. See
  [Web UI](https://nxplain-sh.github.io/goethite/web-ui/#the-cluster-page).
- **Compose files** for Docker Compose and Podman Compose, on the minor version's tag, with a
  read-only root file system and no way to gain privileges.
  `deploy/container/compose.yaml` runs one node as an unprivileged user from the start, with no
  capabilities ([Install](https://nxplain-sh.github.io/goethite/install/#in-a-container)).
  `deploy/container/cluster/` runs a cluster, one machine per member: goethite and the floating
  IP's `goethite vrrp` on each DNS node, the witness unprivileged on a third, with example config
  files for each ([High availability](https://nxplain-sh.github.io/goethite/ha/#in-containers)).
  See [ADR 0036](docs/adr/0036-compose-files.md).

### Changed

- **Metrics are kept by the OpenTelemetry SDK** ([ADR 0034](docs/adr/0034-opentelemetry.md)),
  the first step towards OpenTelemetry for metrics, logs and traces. `/metrics` serves the same
  families, labels, help and types as before, through the SDK's Prometheus reader, so scrapes and
  dashboards keep working. Small differences:
  - the upstream metrics list their labels in another order (`protocol` first), which Prometheus
    ignores;
  - `goethite_query_duration_seconds_sum` is a sum of seconds rather than of whole microseconds.

  The per-query counters are bound instruments, about 11 ns per query (see
  [`bench/`](bench/README.md#query-metrics)). An OpenTelemetry Collector can read `/metrics` with
  its `prometheus` receiver ([API docs](https://nxplain-sh.github.io/goethite/api/#metrics)).
- goethite is now licensed under the GNU Affero General Public License, version 3 only
  (`AGPL-3.0-only`), instead of MIT OR Apache-2.0. Releases up to and including v0.5.0 keep MIT OR
  Apache-2.0. Contributions come in under Apache-2.0
  ([ADR 0033](docs/adr/0033-agpl-license.md)).
- **The website is built with TanStack Start** instead of Astro Starlight: every page is still
  static HTML at the same address, with the same docs, search, light and dark themes and API
  reference. The web UI and the site build with [Vite+](https://viteplus.dev), which adds a
  formatter, a linter and type-aware lint checks (`npm run check`) to both
  ([ADR 0035](docs/adr/0035-site-on-tanstack-start-and-vite-plus.md)).
- The container image is built on Debian 13 (`gcr.io/distroless/cc-debian13`): the Debian 12
  images it was built on were deprecated on 1 September 2026 and no longer get security fixes. It
  also carries the standard OCI labels (version, commit, documentation), on the multi-architecture
  image's index too, where ghcr.io looks for its description.

### Removed

- **The Terraform provider.** Its repository is gone, and `managed_by` no longer has a `terraform`
  value: resources that had it read as `api`, so the web UI and the TUI no longer show anything
  read-only, and a request that sends `terraform` gets `api`
  ([ADR 0034](docs/adr/0034-drop-the-terraform-provider.md)). A provider may come back later.

### Fixed

- Deleting a filter list in the web UI no longer fails with a conflict when a group started using
  it after the page loaded, such as the default group just after the list was created: the UI
  checks which groups use the list at the moment it deletes it.

## [0.5.0] - 2026-10-09

Phase 5, v0.5: Raft clustering with a witness, a Landlock and seccomp sandbox, reproducible and
signed releases with packages and a container image, access control and rate limits on every
transport, local DNS records, and moving from Pi-hole or AdGuard Home. Fuzzing moved out of
public CI. This version is the one the external security review looks at
([docs/security-review.md](docs/security-review.md)).

### Added

- **A sandbox on Linux.** Once its privileges are gone, goethite confines itself: Landlock lets
  `goethite run` read only the system directories, its config, certificates and local lists, and
  change only its store, downloaded lists and runtime directory, with no new TCP listeners; a
  seccomp filter refuses mounting, modules, `ptrace`, BPF, `io_uring`, new namespaces and other
  system calls goethite never makes, and sockets other than IPv4, IPv6 and Unix ones.
  `goethite witness` may change only its store and start no program; `goethite vrrp` may open no
  file. Upgrades work inside it: the new goethite starts within the old one's sandbox. Older
  kernels get what they support, and the log says what is in force; `[security] sandbox = false`
  turns it off. See [Security](https://nxplain-sh.github.io/goethite/security/#the-sandbox) and
  [ADR 0032](docs/adr/0032-sandbox.md).
- **Raft clustering, with a witness.** The members of a cluster agree on every configuration
  change with Raft (openraft) and apply it in the same order; one leads, and the others forward
  changes to it. With two nodes and a witness (`goethite witness`, which votes, never leads and
  serves no DNS; `goethite-witness.service`), or three nodes, losing any one elects a new leader
  within seconds (5 to 12 in the chaos lab) and changes go on. Members are listed in
  `[[cluster.member]]`, one node starts the cluster with `bootstrap = true`, and the leader adds
  the others as they answer, making them voters once that makes three or more. `GET /api/v1/cluster` adds the members, the
  leader, the term and this node's state; `DELETE /api/v1/cluster/members/{node}` removes a
  member. Every member's audit log holds the cluster's changes, by their real actors. See
  [High availability](https://nxplain-sh.github.io/goethite/ha/) and
  [ADR 0031](docs/adr/0031-raft-clustering.md).
- **Release builds.** `cargo xtask dist` builds the release tarball and SBOMs for the machine's
  architecture in a pinned image, from the last commit; the same commit gives the same bytes. The
  release workflow builds amd64 and arm64 twice on separate runners and stops unless the bytes
  match; on a tag it attests the build provenance and the SBOMs with keyless Sigstore signatures
  and drafts a GitHub Release. Each tarball holds the binary (web UI included, with its
  dependency list embedded by cargo-auditable), the systemd units and the example config; the
  binaries need glibc 2.34 or newer. See
  [Verifying releases](https://nxplain-sh.github.io/goethite/verify/) and
  [ADR 0026](docs/adr/0026-release-builds.md).
- **Packages and a container image.** Each release has a .deb and an .rpm per architecture and a
  container image, `ghcr.io/nxplain-sh/goethite`, all holding the release binary and attested
  like it. The packages install the units and a server config, start nothing on first install,
  and on upgrade hand over to the new binary in place without dropping a query. The image is
  distroless; goethite binds port 53 as root there, then runs as an unprivileged user. The
  tarball ships the same server config as `goethite.toml`. See the
  [install guide](https://nxplain-sh.github.io/goethite/install/) and
  [ADR 0027](docs/adr/0027-packages-and-container-image.md).
- **Third-party licence notices.** Releases include `THIRD-PARTY-LICENSES.txt` with the notices
  of every crate and npm package built into the binary; the packages install it in
  `/usr/share/doc/goethite`.
- **`goethite migrate pihole|adguard-home`** reads a running Pi-hole v6 or AdGuard Home through
  its web API and brings lists, rules, groups, clients, local records and settings over through
  goethite's API, showing first what comes over, what behaves differently and what is left out.
  Applying only adds what goethite lacks, so it can run again. See
  [Moving from Pi-hole or AdGuard Home](https://nxplain-sh.github.io/goethite/migrate/) and
  [ADR 0030](docs/adr/0030-migrating-from-pihole-and-adguard-home.md).
- **Local DNS records.** goethite answers names of your own, `A`, `AAAA` and `CNAME`, exact or a
  wildcard (`*.home.example`), for every client and before the filter: in the web UI's Records
  page or `/api/v1/records`. A `CNAME` is followed, and its target resolved like any other name.
  See [Local records](https://nxplain-sh.github.io/goethite/local-records/) and
  [ADR 0029](docs/adr/0029-local-dns-records.md).
- **Access control.** Allowed and blocked clients, by address, network or client ID, for every
  transport: a query is answered when its client is allowed (or nobody is listed) and not
  blocked. Refused UDP queries get no answer, refused connections are closed before their TLS
  handshake, and a client ID refused after the handshake gets `REFUSED`. The lists are part of
  the replicated settings (`access` in `/api/v1/settings`, the web UI's Settings), so they apply
  at once on every node. Loopback addresses always pass. Counted in
  `goethite_access_refused_total{protocol}`.
- **Rate limiting over every transport.** TCP, DNS over TLS, HTTPS and QUIC queries count against
  the same per-client limit as UDP; over it, they get `REFUSED` and are not logged. Oblivious DoH
  stays limited by connections only. `[server.rate_limit] exempt` lists networks that are never
  limited.
- `cargo xtask versions`, also in CI: the internal crates and the web UI carry the workspace
  version.

### Changed

- **Breaking: lists given by a path must be in one directory**, `[filter] local_lists_dir`, by
  default `lists` beside the config file (`/etc/goethite/lists`, which the packages and the image
  now create). goethite reads lists from nowhere else, whether they come from the config file or
  the API: move list files there. A list elsewhere is skipped, with its status and the log saying
  why, and `goethite check-config` fails on it.
- openraft, which logs every election and membership change, logs only warnings unless
  `RUST_LOG` names it: goethite logs those events itself.
- **Clusters run on Raft instead of primary and replica** (ADR 0031 supersedes ADR 0010).
  goethite 0.4's `[cluster]` tables keep working: the primary starts the cluster with its
  configuration, the replica is added to it, and two nodes alone still have one voter. `promote`
  now takes a cluster that cannot elect a leader over, as a new cluster with this node's
  configuration (refused while a leader answers); `demote` leaves a cluster to join another.
  Upgrade both nodes; configuration changes are refused until they run the same version. The web
  UI and the TUI show the leader and how many members are up. `goethite import` refuses to run on
  a node in a cluster: change the cluster's configuration through any member's API.
- **The store's schema is version 2** (local records). In a cluster, a replica copies only from a
  primary on the same version: upgrade both nodes, the replica first, as usual. An older store
  gains the new table when opened.
- `goethite_rate_limited_total` has a `protocol` label, now that every transport is limited; sum
  it for the old total.
- **Fuzzing no longer runs in public CI**, where a crash it found would be public before its
  fix: `cargo xtask fuzz` runs every target locally, as a release step, on a nightly pinned in
  `fuzz/rust-toolchain.toml`, and CI only builds the targets
  ([ADR 0028](docs/adr/0028-fuzzing-off-public-ci.md)).
- The API reference's npm package (`@scalar/api-reference`) is a runtime dependency of the web UI
  rather than a development one: its bundle ships in the binary, so the web UI's SBOM and the
  licence notices now include it and the packages it bundles.
- **The systemd units moved from `dist/systemd/` to `deploy/systemd/`.** Install them from the
  new path; the units themselves are unchanged.
- Release builds use thin LTO and one codegen unit: the binary is about a quarter smaller
  (24.9 to 19.0 MB on macOS arm64) and lookups move by a few nanoseconds either way
  ([bench/README.md](bench/README.md#release-profile)).
- The repository follows the
  [standard Rust project layout](https://github.com/miguelmartens/standard-rust-project-layout),
  with its deviations recorded in [ADR 0025](docs/adr/0025-standard-rust-project-layout.md):
  `cargo xtask ci` runs every check CI runs, CI also checks rustdoc and the shell scripts, every
  public type has a `Debug` that prints no secrets, fuzz targets are kebab-case
  (`cargo fuzz run decode-query`), and `.env` files are ignored, with `.env.example` listing the
  variables goethite reads.

## [0.4.0] - 2026-10-08

Phase 4, v0.4: the full web UI, DNS over TLS, HTTPS and QUIC and Oblivious DoH for clients,
recursion with DNSSEC validation, recommended lists and blocked services, the DNS leak test and
EDNS padding.

### Added

- **DNS over TLS and DNS over HTTPS for clients** (RFC 7858, RFC 8484), configured in
  `[server.tls]`: GET and POST at `/dns-query`, over HTTP/1.1 and HTTP/2, with the same connection
  limits as TCP. `SIGHUP` reloads renewed certificates, for the API too, without dropping a
  connection; `check-config` checks them. The new listeners are handed over on upgrades and kept
  by systemd across restarts.
- **Client IDs**: a client can be known by up to 16 IDs as well as, or instead of, its
  addresses. A device names itself in the DNS over HTTPS path (`/dns-query/anna-phone`) or the
  TLS server name (`anna-phone.dns.example`), so its filtering follows it off the network. The
  web UI shows the values to set a device up with; the TUI lists them.
- **DNS over QUIC for clients** (RFC 9250): `doq` addresses in `[server.tls]`, with client IDs in
  the server name. A client's address is checked with a QUIC Retry before its connection counts
  against the connection limits, which it shares with TCP, DoT and DoH; 0-RTT is refused. DoQ
  sockets are handed over on upgrades too.
- **Recursive resolution**: `[recursion] enabled = true` resolves every name from the root
  servers down instead of asking `[[upstream]]` resolvers, so no upstream sees your network's
  names. QNAME minimisation (RFC 9156) is on; servers are believed only about their own zones;
  every query gets a random port, ID and 0x20 case; everything is bounded per client query.
  Special-use names and private reverse zones are answered without asking anyone. The query log
  shows the server that answered, and the status API, metrics, web UI and TUI show recursion's
  counters.
- **EDNS padding** (RFC 7830, RFC 8467 block sizes): answers to padded queries over DoT, DoH and
  DoQ are padded to 468-byte blocks, and goethite's queries to DoT and DoH upstreams to 128-byte
  blocks, so message sizes say less about the names in them.
- The web UI links to the documentation and the API reference from the top bar of every page and
  the sign-in page; the API reference is the node's own when it serves one to the browser.
  `/api/v1/status` says whether it does (`api_docs`).
- **DNS leak test**: the web UI's Leak test page has the browser look up names only goethite
  answers, and says whether this device's lookups reach goethite (all, some or none), over which
  protocol, from which address, as which client and group, and whether filtering applies. A
  router forwarding lookups shows up as another address. The TUI lists tests and tests its own
  machine (`t`); the API has `/api/v1/leak-tests`. Everything under `goethite.test` is now
  answered by goethite itself, never forwarded.
- **DNSSEC validation** of recursive answers, on by default (`[recursion] dnssec`): signed
  answers get the AD flag, bogus ones are refused with SERVFAIL, and clients that set DO get the
  signatures and NSEC/NSEC3 proofs. Built-in root trust anchors (KSK-2017 and KSK-2024); RSA,
  ECDSA and Ed25519; bounded against KeyTrap and costly NSEC3. New metric
  `goethite_recursion_dnssec_total`; status, web UI and TUI show secure, insecure and bogus
  counts.
- **Oblivious DNS over HTTPS** (RFC 9230), as a target: `odoh = true` in `[server.tls]` answers
  encrypted queries a proxy forwards at `/dns-query`, and serves the public key at
  `/.well-known/odohconfigs`. Keys are kept in memory only and rotated daily; the previous key is
  accepted for a day. Queries are logged and counted as `odoh`; `/api/v1/status` says whether
  ODoH is on, and the client editor shows the target address.
- `require_client_id` in `[server.tls]` answers only encrypted queries with a known client ID, for
  listeners reachable from the internet.
- The query log and metrics tell `dot`, `doh` and `doq` apart from `udp` and `tcp`; the web UI's query
  log marks encrypted queries. New metrics: `goethite_tls_handshake_failures_total` and
  `goethite_https_rejected_total`. `/api/v1/status` reports the encrypted listeners.

- **The full web UI**: lists, rules, groups, clients, schedules, settings and the audit log can
  be viewed and changed from the browser. Changes carry the revision you saw, so a change made
  meanwhile is offered instead of overwritten; what Terraform manages is read-only; a list, a
  schedule or a group that is still in use says what uses it. New lists can join the default
  group at once.
- **The API reference in the binary**, at `/api/docs` with `[api] docs = true`: Scalar, built in,
  for loopback clients only.
- Web UI tests: Vitest for the forms' logic, and Playwright end-to-end tests against a real
  goethite, in CI.

- **Recommended filter lists and presets**: 36 lists, each checked, by category: one base list
  against ads and trackers (★ HaGeZi Multi Normal, Multi Pro, OISD Big, and others for minimal,
  aggressive or compatible blocking), security lists to stack on it (★ HaGeZi TIF Mini and Fake,
  and more), optional lists by topic (bypass prevention, device trackers, family, hardening) and
  legacy ones. The Lists page warns when two base lists overlap, switches rather than stacks
  lists that do the same job, and shows sizes from each list's header, or what goethite read
  with the lines it skipped. Presets (Balanced, Strict, Family, Don't break anything) set a
  group's lists in one step after showing what changes. `GET /api/v1/lists/recommended` and
  `/api/v1/lists/recommended/sizes`. A new node starts with the Balanced preset (HaGeZi Multi
  Normal, TIF Mini and Fake) in its default group, unless its config file names lists or sets
  `[filter] default_lists = false`; existing nodes do not change.
- A byte order mark at the start of a list file is no longer read as part of its first line.
- **Find lists in the FilterLists directory** (filterlists.com) from the Lists page: the node
  fetches the directory when someone browses it, keeps it a day, and shows only the lists
  goethite can read, allowlists left out. `GET /api/v1/lists/directory`;
  `[filter] directory = false` turns it off.
- **An interactive dashboard**: 24 hours, 7 days or 30 days; tiles, top names and clients and the
  chart's bars open the query log filtered to them; the chart (now TanStack Charts) shows each
  bar's counts on hover or keyboard focus; a top blocked name can be allowed, and a top name
  blocked, from the dashboard. The query log shows client and time filters as chips, and dates
  for entries from other days.
- **Blocked services**: a group blocks a whole service, such as TikTok, YouTube or Roblox, with a
  toggle in the web UI, always or during a schedule, whatever its lists say
  (`blocked_services` on groups). The services and their rules are AdGuard's HostlistsRegistry
  catalog, which the node downloads with the lists (`GET /api/v1/services`; `[filter] services`
  and `services_file`). The query log names the service that blocked a query; the TUI counts a
  group's blocked services.
- `until` on `GET /api/v1/querylog`: only entries before a time, for time windows with `since`.

- **A Terraform and OpenTofu provider**, in its own repository
  ([nxplain-sh/terraform-provider-goethite](https://github.com/nxplain-sh/terraform-provider-goethite)):
  lists, rules, groups, clients, schedules and settings, generated from goethite's OpenAPI
  document. A new guide on the website explains how to use it.

- Fuzz targets `parse_doh`, `parse_doq`, `parse_odoh`, `classify_response`, `check_dnssec`,
  `parse_filterlists`, `parse_services` and `parse_leak_probe`.

### Changed

- The web UI has one theme, light, whatever the system prefers; the theme switch in its header
  is gone.
- Settings moved from the web UI's page tabs to its header, beside Pause and Sign out.

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

[Unreleased]: https://github.com/nxplain-sh/goethite/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/nxplain-sh/goethite/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/nxplain-sh/goethite/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/nxplain-sh/goethite/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nxplain-sh/goethite/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nxplain-sh/goethite/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nxplain-sh/goethite/releases/tag/v0.1.0
