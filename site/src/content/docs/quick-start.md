---
title: Quick start
description: Build goethite from source and query the development server.
---

goethite is **pre-alpha**. It forwards queries to the upstream resolvers you configure, over DNS
over TLS, DNS over HTTPS or plain DNS, with failover, caches the answers, and blocks names from
filter lists (see [Filtering](../filtering/)).

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

It forwards to [Quad9](https://quad9.net/) (`9.9.9.9`, then `149.112.112.112`) over DNS over TLS.
goethite never picks an upstream for you: the config must list at least one `[[upstream]]`:

```toml
[[upstream]]
address = "9.9.9.9"          # an IP address; the port defaults to the protocol's
protocol = "tls"             # "tls", "https", "udp" or "tcp"
tls_name = "dns.quad9.net"   # the name the certificate must be valid for

[[upstream]]
address = "9.9.9.9"
protocol = "https"
url = "https://dns.quad9.net/dns-query"
```

Certificates are checked against the Mozilla root certificates built into goethite.

## Check a config

`check-config` reads a config file, builds the upstreams and compiles the filter lists as `run`
would, without binding a socket or downloading anything, and exits with status 1 if something is
wrong:

```sh
cargo run -- check-config --config config/goethite.example.toml
```

It is stricter than startup about filter lists: at startup a list file that cannot be read is
logged and skipped so that resolution keeps working, while `check-config` reports it as an error.
Rules written into the config itself (`[filter] rules`) are always checked strictly; a rule
goethite does not support stops the server from starting, since it is most likely a typo.

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

`goethite.test` is answered by goethite itself, which makes it a handy liveness check. Every
other name is forwarded upstream:

```sh
dig @127.0.0.1 -p 15353 example.com
```

The header shows `ra` (recursion available) and the answer comes from Quad9, over an encrypted
connection:

```text
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
```

Ask again and the answer comes from goethite's cache: the query time drops to about 0 ms and the
TTL has counted down. The `[cache]` table in the config sets its size and TTL limits.

The same queries work over TCP:

```sh
dig @127.0.0.1 -p 15353 +tcp example.com
```

## Watch it

The [terminal UI](../tui/) shows the dashboard, the query log and the filter lists:

```sh
cargo run -- tui
```

The [web UI](../web-ui/) shows the same in a browser at `http://127.0.0.1:8053/`. It is built
separately with Node.js 24 or later; build it once, before or while goethite runs:

```sh
cd web && npm ci --ignore-scripts && npm run build
```

## Stop it

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> (or send `SIGTERM`). goethite stops accepting new queries,
finishes answering queries already in progress (for up to 5 seconds), closes open TCP
connections, and exits.
