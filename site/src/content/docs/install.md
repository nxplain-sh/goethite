---
title: Install on Linux
description: Build goethite, install it with the hardened systemd unit, and point your network at it.
---

goethite runs on Linux on amd64 and arm64. There are no prebuilt packages yet, so this guide
builds it from source and installs it with the systemd unit from the repository. (macOS works for
development only; see the [quick start](../quick-start/).)

## Build

Install Rust with [rustup](https://rustup.rs), a C compiler (`build-essential` on Debian and
Ubuntu, `gcc` elsewhere) and Node.js 24 or later (for the web UI only), then:

```sh
git clone https://github.com/nxplain-sh/goethite && cd goethite
(cd web && npm ci --ignore-scripts && npm run build)
cargo build --release --locked
```

The binary is `target/release/goethite`, with the [web UI](../web-ui/) inside. It has no runtime
dependencies beyond the C library; Node.js is needed only to build. Skip the `web` line to build
without the web UI.

## Install

```sh
sudo install -m 0755 target/release/goethite /usr/bin/goethite
sudo install -m 0644 dist/systemd/goethite.service /etc/systemd/system/goethite.service
sudo install -d -m 0755 /etc/goethite
sudo install -m 0644 config/goethite.example.toml /etc/goethite/goethite.toml
```

Then edit `/etc/goethite/goethite.toml` for production. At least:

```toml
[server]
listen = ["0.0.0.0:53", "[::]:53"]   # or the host's own addresses, see below

[filter]
cache_dir = "/var/lib/goethite/lists"

[[filter.list]]
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

The example config forwards to Quad9 over DNS over TLS; change the `[[upstream]]` tables to use
another resolver. The [configuration reference](../configuration/) lists every setting. Check
the result before starting:

```sh
goethite check-config --config /etc/goethite/goethite.toml
```

## Start

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now goethite
journalctl -u goethite -f
```

The log shows the upstreams, the lists as they load and download, and one `listening` line per
address. Test it from another machine:

```sh
dig @192.0.2.10 example.com          # use the server's address
dig @192.0.2.10 doubleclick.net      # 0.0.0.0: blocked
```

`sudo systemctl reload goethite` re-reads the filter lists. Changes to the config file itself take
effect with an upgrade in place (below), or with `sudo systemctl restart goethite`; changes to
listen addresses need the restart.

The unit runs goethite as a dynamic, unprivileged user. It may bind port 53, and gives that up as
soon as its sockets are bound. The only writable directory is `/var/lib/goethite`. See
[Security settings](../security/#privileges) for what the sandbox does, and run
`systemd-analyze security goethite` to review it.

### Port 53 is already in use

On many distributions `systemd-resolved` listens on `127.0.0.53:53`, and a wildcard address such
as `0.0.0.0:53` then fails with "address in use". Either list the server's own addresses instead
of `0.0.0.0` (`listen = ["192.0.2.10:53", "[2001:db8::10]:53"]`), or turn off resolved's stub
listener:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/goethite.conf
sudo systemctl restart systemd-resolved
```

Listing addresses explicitly is also better on a host with several addresses: a socket bound to
`0.0.0.0` may answer from a different address than the one a client asked.

### Without systemd

Start goethite as root with a user to switch to after binding:

```toml
[server]
user = "goethite"   # an unprivileged user from /etc/passwd
```

The user needs to read the config and the lists, and to write the `cache_dir`.

## Manage it

goethite's [REST API](../api/) listens on `127.0.0.1:8053`, so on the server itself you can, for
example, check on it with `curl http://127.0.0.1:8053/api/v1/status`. To manage it from another
machine, create an admin token with `goethite token`, put the printed hash in the `[api]` table,
and preferably serve HTTPS with your own certificate. Clients, groups, schedules, lists and rules
are all managed through the API (see [Clients and groups](../groups/)).

## Point your network at it

Hand out goethite's address as the DNS server in your router's DHCP settings, or configure it on
each device. Two goethite nodes can share one address that whichever is healthy holds: see
[High availability](../ha/#a-floating-ip).

Keep goethite on your network: do not expose port 53 to the internet. Rate limiting stops the
worst abuse, but an open resolver still attracts it.

## Upgrade

Build the new version, install it, and ask the running goethite to hand over to it:

```sh
sudo install -m 0755 target/release/goethite /usr/bin/goethite
sudo goethite check-config --config /etc/goethite/goethite.toml
sudo systemctl kill --signal=SIGUSR2 --kill-whom=main goethite
```

goethite starts the new binary and hands it its sockets and its store; the new one starts
answering, and the old one finishes the queries it was answering and exits. No query is dropped,
and the log says `answering in place of the previous goethite`. If the new one fails to start,
the old one says `the upgrade failed, carrying on` and goes on as if nothing happened. The new one
also re-reads the config file, so this applies config changes too, except new listen addresses.

`sudo systemctl restart goethite` works too: systemd keeps goethite's sockets across the restart,
so queries wait in the kernel for the second or so it takes rather than being refused. The same
happens if goethite crashes and systemd restarts it.

Read the [changelog](../changelog/) first: before 1.0, a minor version may change the
configuration format, and `goethite check-config` tells you what to fix.
