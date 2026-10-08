# goethite

A self-hosted, clustered, security-hardened DNS filtering resolver written in Rust.

goethite aims to be a better self-hosted alternative to Pi-hole, AdGuard Home, NextDNS and Numa on
**security**, **performance** and **high availability**, while matching AdGuard Home on everyday
filtering features: caching and forwarding, encrypted DNS, per-client groups and schedules,
AdGuard/uBlock filter syntax, CNAME uncloaking, and a replicated cluster with a floating IP and
zero-downtime upgrades. It is named after the iron-oxide mineral that is a main component of rust.

## Status

**Pre-alpha, v0.1.0.** goethite forwards queries to the upstream resolvers you
configure, over DNS over TLS, DNS over HTTPS or plain DNS, with failover; caches the answers; and
blocks names from hosts files, domain lists and AdGuard-style rules, from local files or downloaded
and refreshed over HTTPS. It protects against DNS rebinding, rate limits clients, drops its
privileges after binding port 53, and ships a hardened systemd unit
([`dist/systemd/`](dist/systemd/goethite.service)). See the roadmap
in [`AGENTS.md`](AGENTS.md#roadmap-respect-the-order).

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

## Repository layout

| Path                        | Purpose                                                                 |
| --------------------------- | ----------------------------------------------------------------------- |
| `crates/goethite-proto`     | DNS wire format; wraps hickory-proto behind our own trait and types     |
| `crates/goethite-filter`    | Rule parsing (hosts, domain lists, AdGuard syntax) and FST/Bloom compiler |
| `crates/goethite-resolver`  | Cache, forwarding, upstream pool; later recursion and DNSSEC            |
| `crates/goethite-server`    | Listeners: UDP/TCP now; DoT, DoH, DoQ later                             |
| `crates/goethite-cluster`   | Config sync and VRRP; later Raft                                        |
| `crates/goethite-api`       | REST API (`/api/v1`) with OpenAPI                                       |
| `crates/goethite-store`     | Embedded storage for query log, stats and config                        |
| `crates/goethite-tui`       | Terminal UI that talks to the API                                       |
| `crates/goethite`           | The binary: CLI, wiring, signal handling                                |
| `web/`                      | Embedded web UI (placeholder until Phase 2)                             |
| `site/`                     | Project website and docs (Astro Starlight), deployed to GitHub Pages    |
| `fuzz/`                     | cargo-fuzz targets                                                      |
| `dist/`                     | Deployment files: the hardened systemd unit                             |
| `docs/`                     | Threat model, ADRs, backlog                                             |

Several crates are still empty skeletons. Benchmarks and how to record them are in
[`bench/`](bench/README.md).

## Documentation

- Website: <https://nxplain-sh.github.io/goethite/>
- [Contributing](CONTRIBUTING.md): build, test, fuzz, commit conventions
- [Security policy](SECURITY.md): how to report vulnerabilities
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture decision records](docs/adr/)
- [Backlog](docs/BACKLOG.md): work noticed now that belongs to later phases

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
