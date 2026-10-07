---
title: Quick start
description: Build goethite from source and query the development server.
---

goethite is **pre-alpha**. The server currently answers a single hardcoded test name, which is
enough to check that the build, the listeners and the DNS wire-format handling work.

## Prerequisites

- **Rust**, installed with [rustup](https://rustup.rs). The repository pins its toolchain in
  `rust-toolchain.toml`, so rustup installs the right version on the first build.
- **dig** (from BIND's `dnsutils` / `bind-tools` package) to send test queries.

## Build and run

```sh
git clone https://github.com/nxplain-sh/goethite && cd goethite
cargo run -- run --config config/goethite.example.toml
```

The example config binds to `127.0.0.1:15353`, so the development server runs without root.
(Port 5353 is avoided because multicast DNS already uses it on most desktops.)
Production deployments use port `53`.

## Query it

In another terminal:

```sh
dig @127.0.0.1 -p 15353 goethite.test
```

The answer section contains `127.0.0.53`:

```text
;; ANSWER SECTION:
goethite.test.		60	IN	A	127.0.0.53
```

Every other name is refused:

```sh
dig @127.0.0.1 -p 15353 example.com
```

```text
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 4242
```

The same queries work over TCP:

```sh
dig @127.0.0.1 -p 15353 +tcp goethite.test
```

## Stop it

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> (or send `SIGTERM`). goethite stops accepting new queries,
finishes answering queries already in progress (for up to 5 seconds), closes open TCP
connections, and exits.
