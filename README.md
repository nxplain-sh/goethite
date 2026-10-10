# goethite

A self-hosted, clustered, security-hardened DNS filtering resolver written in Rust.

goethite puts **security**, **performance** and **high availability** first, and covers the
everyday features of a network-wide DNS filter: caching and forwarding, encrypted DNS, per-client
groups and schedules, AdGuard/uBlock filter syntax, CNAME uncloaking, and a replicated cluster with
a floating IP and zero-downtime upgrades. It is named after the iron-oxide mineral that is a main
component of rust.

## Status

**Pre-alpha, v0.5.0.** goethite forwards queries to the upstream resolvers you configure, over
DNS over TLS, DNS over HTTPS or plain DNS, with failover, or resolves every name itself from the
root servers down, with QNAME minimisation and DNSSEC validation. It caches the answers, answers
your own names (local DNS records), and blocks names from hosts files, domain lists and
AdGuard-style rules, from local files or downloaded and refreshed over HTTPS; a new node starts
with a recommended set of lists, and a whole service (TikTok, YouTube, ...) can be blocked per
group. Clients can reach it over DNS over TLS, HTTPS and QUIC, or Oblivious DNS over HTTPS, be
known by a client ID wherever they are, and be allowed or refused by address or ID. Clients can
be put in groups with their own lists, schedules and safe search, and blocking sees through CNAME
cloaking. It keeps a query log and statistics, exports Prometheus metrics, and is managed through
a REST API (with an OpenAPI description), a terminal UI and a web UI; every change is
audit-logged, a DNS leak test shows whether a device's lookups reach it, and `goethite migrate`
brings a Pi-hole's or AdGuard Home's configuration over. Nodes form a cluster that agrees on one
configuration with Raft, with a vote-only witness so two nodes survive losing either, and share a
floating IP over VRRP; goethite upgrades without dropping a query. It protects against DNS
rebinding, rate limits clients, pads encrypted messages, drops its privileges after binding port
53, then confines itself with Landlock and seccomp, and ships hardened systemd units
([`deploy/systemd/`](deploy/systemd/)). See the [changelog](CHANGELOG.md).

Releases are built reproducibly, with signed build provenance and SBOMs, as tarballs, `.deb` and
`.rpm` packages for amd64 and arm64, and a container image (`ghcr.io/nxplain-sh/goethite`, with
[Compose files](deploy/container/) for one node and for a cluster): see
[Install](https://nxplain-sh.github.io/goethite/install/) and
[Verifying releases](https://nxplain-sh.github.io/goethite/verify/).

## Quick start (development)

Requires Rust via [rustup](https://rustup.rs). The pinned toolchain (1.99.0) installs automatically
from `rust-toolchain.toml`.

```sh
cargo run -- run --config config/goethite.example.toml
```

In another terminal:

```sh
dig @127.0.0.1 -p 15353 goethite.test        # -> 127.0.0.53, answered by goethite itself
dig @127.0.0.1 -p 15353 example.com          # -> forwarded to Quad9 over DNS over TLS
dig @127.0.0.1 -p 15353 example.com +tcp     # same, client side over TCP
dig @127.0.0.1 -p 15353 doubleclick.net      # -> 0.0.0.0, blocked by the example rules
```

The example config forwards to Quad9 over DNS over TLS. Upstreams are configured in
`[[upstream]]` tables (`udp`, `tcp`, `tls` or `https`) and at least one is required; see
[`config/goethite.example.toml`](config/goethite.example.toml).

Development binds to `127.0.0.1:15353`, so no root is needed (port 5353 is avoided because
multicast DNS already uses it on most desktops). Logs go to stderr and are controlled
by `RUST_LOG` (default `info`; malformed packets are logged at `debug`):

```sh
RUST_LOG=debug cargo run -- run --config config/goethite.example.toml
```

Ctrl-C or `SIGTERM` shuts the server down gracefully. `goethite check-config --config <path>`
checks a config file and its filter lists without starting the server.

While it runs, `cargo run -- tui` opens the terminal UI, and the REST API answers on
`http://127.0.0.1:8053/api/v1` (see the [API docs](https://nxplain-sh.github.io/goethite/api/)).
The web UI is at `http://127.0.0.1:8053/` once it is built (Node.js 24+):

```sh
cd web && npm ci --ignore-scripts && npm run build
```

## Repository layout

| Path                        | Purpose                                                                 |
| --------------------------- | ----------------------------------------------------------------------- |
| `crates/goethite-proto`     | DNS wire format; wraps hickory-proto behind our own trait and types     |
| `crates/goethite-filter`    | Rule parsing (hosts, domain lists, AdGuard syntax) and FST/Bloom compiler |
| `crates/goethite-resolver`  | Cache, forwarding, recursion with DNSSEC validation                     |
| `crates/goethite-server`    | Listeners: UDP, TCP, DoT, DoH, DoQ; the Oblivious DoH target            |
| `crates/goethite-cluster`   | Raft for the config (openraft), the witness, and VRRP                   |
| `crates/goethite-api`       | REST API (`/api/v1`) with OpenAPI                                       |
| `crates/goethite-store`     | Embedded storage for query log, stats and config                        |
| `crates/goethite-tui`       | Terminal UI that talks to the API                                       |
| `crates/goethite-migrate`   | Plans a migration from Pi-hole or AdGuard Home (`goethite migrate`)     |
| `crates/goethite`           | The binary: CLI, wiring, signal handling                                |
| `xtask/`                    | Repository automation: `cargo xtask ci` runs the checks CI runs         |
| `web/`                      | Web UI (Vite+, React, TanStack Router), embedded into the binary        |
| `site/`                     | Project website and docs (TanStack Start), deployed to GitHub Pages     |
| `fuzz/`                     | cargo-fuzz targets                                                      |
| `tests/chaos/`              | Chaos tests: two nodes, a witness and a client in network namespaces    |
| `tests/packages/`           | Installs the .deb and .rpm on each supported distribution               |
| `deploy/`                   | Systemd units, server config, package and container image definitions   |
| `config/`                   | The example configuration                                               |
| `docs/`                     | Threat model, ADRs, backlog                                             |

Benchmarks and how to record them are in [`bench/`](bench/README.md). The layout follows the
[standard Rust project layout](https://github.com/miguelmartens/standard-rust-project-layout);
[ADR 0025](docs/adr/0025-standard-rust-project-layout.md) records where goethite deviates from it.

## Documentation

- Website: <https://nxplain-sh.github.io/goethite/>
- [Contributing](CONTRIBUTING.md): build, test, fuzz, commit conventions
- [Security policy](SECURITY.md): how to report vulnerabilities
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture decision records](docs/adr/)
- [Backlog](docs/BACKLOG.md): work noticed along the way and not scheduled yet
- [Competitor features](docs/competitor-features.md): AdGuard Home, Pi-hole and Numa set against
  goethite

## Independent implementation

goethite is its own code, written from scratch. Nothing in it is copied from Pi-hole, AdGuard Home,
NextDNS, Numa or any other DNS filter, translated from another language, or used as a template.
What it does comes from the DNS RFCs, the published formats of the filter lists it reads (hosts
files, domain lists, AdGuard-style rules) and its own design, which the [ADRs](docs/adr/) record.

Other projects were studied, never copied, in two places, both linked so anyone can check them:

- [Competitor features](docs/competitor-features.md) records what the other projects do, citing
  their documentation and source, so goethite can decide what to build. It lists features, not
  code.
- `goethite migrate` reads Pi-hole's and AdGuard Home's web APIs, so the shape of their answers was
  checked against their source, for interoperability only
  ([ADR 0030](docs/adr/0030-migrating-from-pihole-and-adguard-home.md)).

No third-party data is compiled into goethite either: filter lists and AdGuard's blocked-services
catalog (GPL-3.0) are downloaded at runtime from their publishers, under their own licenses
([ADR 0019](docs/adr/0019-blocked-services.md),
[ADR 0022](docs/adr/0022-recommended-list-catalog.md)).
The libraries goethite builds on, such as hickory-proto, are declared dependencies whose licenses
`cargo deny` checks. Contributions are held to the same rule: send only code you wrote yourself.

## License

goethite is free software under the
[GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0-only`). You may run,
study, change and share it. If you distribute it, or run a changed version that others use over a
network (for a DNS server, every client that queries it), you must offer them its source under the
same license.

Releases up to and including v0.5.0 were published under MIT OR Apache-2.0 and keep that license.
[ADR 0033](docs/adr/0033-agpl-license.md) explains the change.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
goethite by you, as defined in the Apache-2.0 license, is licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0), without any additional
terms or conditions. goethite ships it under the AGPL-3.0-only with the rest of the code. Because
Apache-2.0 is permissive, the maintainers can also offer goethite, your contribution included,
under other terms, such as a hosted service or a commercial license.
