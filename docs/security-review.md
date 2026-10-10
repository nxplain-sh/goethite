# External security review: scope for v0.5.0

This is the brief for the external security review of v0.5 (see the
[changelog](../CHANGELOG.md#050---2026-10-09)). It says what goethite is, where its trust
boundaries are, what to look at first, how to build and test it, and which risks are known and
accepted. The [threat model](THREAT_MODEL.md) is the companion document: every boundary (B1 to B8)
and control named here is described there, with the ADR behind it.

## What is under review

goethite v0.5.0: a DNS filtering resolver in Rust (edition 2024, toolchain pinned in
`rust-toolchain.toml`), for Linux on amd64 and arm64. One binary holds the DNS server, the REST
API with an embedded web UI (React, TypeScript), a terminal UI, the cluster (Raft through
openraft), a vote-only witness, a floating-IP helper (VRRP) and an importer. Releases are built
reproducibly and attested ([ADR 0026](adr/0026-release-builds.md)); `cargo xtask dist` rebuilds
them bit for bit, and a release's commit is the tag `v0.5.0` on `main`.

In scope: everything in this repository that ships in the binary, the packages or the image, the
release and CI workflows, and the systemd units. Out of scope: the website (`site/`), macOS and
Windows (development only), and denial of service by traffic volume beyond the documented bounds.

## Where to look first

Ordered by exposure: the first areas take input from anyone on the network.

| # | Area | Boundary | Code | Notes |
| -- | --- | --- | --- | --- |
| 1 | DNS listeners and message parsing | B1 | `crates/goethite-proto`, `crates/goethite-server` | UDP, TCP, DoT, DoH, DoQ, ODoH; access control, rate and connection limits. Fuzz targets `decode-query`, `parse-doh`, `parse-doq`, `parse-odoh`, `parse-leak-probe`, `parse-name` |
| 2 | Resolution: cache, forwarding, recursion, DNSSEC | B2 | `crates/goethite-resolver` | Poisoning, response matching, the iterator's zone checks, the validator's bounds (KeyTrap). Targets `decode-response`, `classify-response`, `check-dnssec` |
| 3 | Filter lists and catalogs | B3 | `crates/goethite-filter`, `crates/goethite/src/{download,lists,filters,services,filterlists,sizes}.rs` | Downloads, parsing, compiling. Targets `parse-list`, `parse-filterlists`, `parse-services` |
| 4 | Cluster | B5 | `crates/goethite-cluster/src/{raft,tls,client,server}*`, `crates/goethite-store/src/store*`, `crates/goethite/src/cluster.rs` | A hostile member: Raft messages, cluster IDs, membership, forwarded changes, the store's apply path. Target `apply-commands` |
| 5 | Admin API and web UI | B4 | `crates/goethite-api`, `web/` | Authentication, loopback rules, CSP, Origin checks, request bounds. Target `request-checks` |
| 6 | Process hardening | B6 | `crates/goethite/src/{privileges,sandbox,handoff,sockets}.rs`, `deploy/systemd/` | Privilege drop, Landlock and seccomp, the upgrade handover |
| 7 | Floating IP | B5 | `crates/goethite-cluster/src/vrrp*`, `crates/goethite/src/vrrp.rs` | Unauthenticated VRRP v3 on a trusted segment. Targets `parse-vrrp`, `parse-netlink` |
| 8 | Importer | B8 | `crates/goethite-migrate`, `crates/goethite/src/migrate.rs` | Answers from the server being migrated. Target `plan-migration` |
| 9 | Release and supply chain | B7 | `xtask/`, `.github/workflows/`, `deny.toml`, `deploy/` | Reproducibility, attestations, pinned actions and images |

### `unsafe`

Every crate forbids `unsafe` except two items, each with a `// SAFETY:` comment:

- `crates/goethite/src/sockets.rs`: adopting the listening sockets systemd passes
  (`OwnedFd::from_raw_fd`), only for this process's `LISTEN_PID`, each descriptor once and checked.
- `crates/goethite-cluster/src/vrrp/arp.rs`: a `sockaddr_ll` for the packet socket that sends
  gratuitous ARP, only in `goethite vrrp`.

Dependencies with `unsafe` of their own that matter most: rustls and ring (TLS), quinn (QUIC),
hickory-proto (DNS wire format, behind goethite's own checks), redb (storage), landlock and
seccompiler (the sandbox's system calls), tokio and hyper.

## Questions we would like answered

- Can a client on the network crash, hang or exhaust a node, or poison its cache, through any
  listener?
- Does the DNSSEC validator accept anything bogus, or burn unbounded work?
- What can a cluster member with a valid certificate do beyond what an admin can? Can a node
  outside the cluster, or a removed member, take part?
- Is the API's authentication, loopback-only mode and CSP sound against browsers and local users?
- Does the sandbox hold: anything `goethite run` can reach that it should not, a way out of
  seccomp's deny-list, a way to break upgrades?
- Can the upgrade handover be hijacked by another local process?
- Are releases reproducible and attested the way [Verifying releases](../site/src/content/docs/verify.md)
  claims?

## How to build, run and test

```sh
cargo xtask ci          # fmt, versions, shellcheck, clippy, docs, tests, cargo-deny, cargo-audit
(cd web && npm ci && npm run check && npm test && npm run e2e)   # the web UI
cargo xtask fuzz        # every fuzz target, 5 minutes each (cargo-fuzz, the nightly in fuzz/)
cargo xtask dist        # the release files for this machine, in a pinned container
sudo tests/chaos/chaos.sh target/release/goethite    # a cluster in network namespaces
tests/packages/install.sh target/dist                # the packages on five distributions
```

A node for poking at: `cargo run -p goethite -- run --config config/goethite.example.toml`
answers DNS on `127.0.0.1:15353` and serves the API and web UI on `127.0.0.1:8053` (no token
needed on loopback until one is configured). The [HA guide](../site/src/content/docs/ha.md) sets
up a cluster; `crates/goethite/tests/cluster.rs` does it with real processes.

## Known and accepted risks

These are documented and not findings by themselves, though better ideas are welcome:

- **VRRP has no authentication** (version 3 dropped it): a host on the segment can take the
  floating IP, as it could with forged ARP ([ADR 0013](adr/0013-floating-ip.md)).
- **Cluster members are as trusted as admins.** A member with a valid certificate can disrupt
  elections and, as leader, write any configuration. Certificates cannot be revoked; removing a
  member for good means a new CA ([ADR 0031](adr/0031-raft-clustering.md)).
- **The sandbox is best effort:** older kernels get part of Landlock or none, outgoing TCP is not
  restricted, `/proc` and the system directories stay readable for `goethite run`, and namespaces
  created through `clone3` are not refused ([ADR 0032](adr/0032-sandbox.md)).
- **Forwarded answers are not DNSSEC-validated**; only recursion validates
  ([ADR 0023](adr/0023-dnssec-validation.md)).
- **Client IDs are names, not secrets**: DoT and DoQ carry them in the clear in the TLS server
  name.
- **Many hosts together can fill the TCP connection slots**; per-client limits stop one.
- **The leak test detects bypasses; it does not prevent them.**
- **Filter lists are trusted to be lists**: HTTPS protects them in transit, nothing authenticates
  their publishers.

## Reporting

Report findings privately as [`SECURITY.md`](../SECURITY.md) describes. Crash inputs from fuzzing
must not be posted publicly before a fix is released.
