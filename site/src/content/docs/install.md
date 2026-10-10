---
title: Install on Linux
description: Install goethite from a package, a tarball or a container image, start it with the hardened systemd unit, and point your network at it.
---

goethite runs on Linux on amd64 and arm64, with glibc 2.34 or newer: RHEL 9, Ubuntu 22.04,
Debian 12 or anything newer. Each [release](https://github.com/nxplain-sh/goethite/releases)
comes as a `.deb` and an `.rpm` package, a tarball and a container image; all of them hold the
same binary, with the [web UI](../web-ui/) inside. (macOS works for development only; see the
[quick start](../quick-start/).)

Every download can be checked with `gh attestation verify` (from the
[GitHub CLI](https://cli.github.com)), which shows that goethite's release workflow built it;
[Verifying releases](../verify/) explains that, and how to rebuild a release yourself and get the
same bytes.

## Install

### From a package

On Debian and Ubuntu:

```sh
version=0.5.0
arch=$(dpkg --print-architecture)    # amd64 or arm64
curl -fLO "https://github.com/nxplain-sh/goethite/releases/download/v$version/goethite_${version}-1_${arch}.deb"
gh attestation verify "goethite_${version}-1_${arch}.deb" --repo nxplain-sh/goethite
sudo apt install "./goethite_${version}-1_${arch}.deb"
```

On RHEL, Rocky, Alma and Fedora:

```sh
version=0.5.0
arch=$(uname -m)    # x86_64 or aarch64
curl -fLO "https://github.com/nxplain-sh/goethite/releases/download/v$version/goethite-${version}-1.${arch}.rpm"
gh attestation verify "goethite-${version}-1.${arch}.rpm" --repo nxplain-sh/goethite
sudo dnf install "./goethite-${version}-1.${arch}.rpm"
```

The package installs `/usr/bin/goethite`, the systemd units, and a config for a server at
`/etc/goethite/goethite.toml`, which upgrades leave as you edited it. It does not start goethite:
[configure](#configure) it first.

### From the tarball

On any distribution with glibc 2.34 or newer:

```sh
version=0.5.0
arch=$(uname -m)    # x86_64 or aarch64
base=https://github.com/nxplain-sh/goethite/releases/download/v$version
curl -fLO "$base/goethite-$version-$arch-unknown-linux-gnu.tar.gz"
gh attestation verify "goethite-$version-$arch-unknown-linux-gnu.tar.gz" --repo nxplain-sh/goethite
tar -xzf "goethite-$version-$arch-unknown-linux-gnu.tar.gz"
cd "goethite-$version-$arch-unknown-linux-gnu"
sudo install -m 0755 goethite /usr/bin/goethite
sudo install -m 0644 systemd/goethite.service /etc/systemd/system/goethite.service
sudo install -d -m 0755 /etc/goethite
sudo install -m 0644 goethite.toml /etc/goethite/goethite.toml
```

`goethite.example.toml` beside it explains every setting.

### In a container

The image is `ghcr.io/nxplain-sh/goethite`, for amd64 and arm64, tagged with each version, its
minor version (`0.5`) and `latest`. The simplest way to run it is the repository's Compose file,
with Docker Compose or Podman Compose:

```sh
gh attestation verify oci://ghcr.io/nxplain-sh/goethite:0.5 --repo nxplain-sh/goethite
mkdir goethite && cd goethite
curl -fLO https://raw.githubusercontent.com/nxplain-sh/goethite/main/deploy/container/compose.yaml
docker compose up -d    # or: podman compose up -d
```

It runs goethite as an unprivileged user (65532) from the start, with no capabilities, no way to
gain any and a read-only root file system, and keeps the store and lists in a volume. It follows
the minor version's tag: `docker compose pull && docker compose up -d` brings a patch release; for
the next minor version, change the tag in the file first. Its comments show how to use your own
config, how to reach the [API](../api/) and the web UI, and what to do where the container runtime
shows every client as one address, which would put your whole network under one client's
[rate limit](../security/#rate-limiting). For a cluster of nodes that share their configuration
and a floating IP, see [High availability](../ha/#in-containers).

Without Compose:

```sh
docker run -d --name goethite --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -v goethite:/var/lib/goethite \
  ghcr.io/nxplain-sh/goethite:0.5.0
```

The image is distroless: no shell, no package manager, the binary and the C library. Started this
way, goethite starts as root to bind port 53 on any runtime, then switches to the unprivileged
user (65532) and gives up every capability before it reads a packet. Its store and lists live in
the `/var/lib/goethite` volume. The image's config listens on IPv4 only, since container networks
often have no IPv6; to change anything, mount your own over `/etc/goethite/goethite.toml`. The API
and the web UI answer inside the container only until you set an admin token there, as below, and
publish port 8053. To upgrade, pull the new tag and recreate the container: unlike the packages, a
container restart drops queries for a second or two.

### On Kubernetes (Helm)

The Helm chart in `deploy/helm/goethite` runs one node: DNS on port 53, the store and the
downloaded lists on a PersistentVolumeClaim, and the image's own config until you set yours.

```sh
git clone --depth 1 https://github.com/nxplain-sh/goethite
helm install goethite ./goethite/deploy/helm/goethite
```

By default the pod runs as 65532 with no capabilities and a sysctl that lets it bind port 53 in
its own network namespace (the same shape as the Compose file above), and in-cluster clients
point at the Service. `--set hostNetwork=true` answers on every node's port 53 instead, where your
whole network can point at it and goethite sees each client's own address; that pod starts as
root to bind the port, as the cluster's Compose files do. Paste a whole `goethite.toml` into the
chart's `config` value to change anything. The [API and the web UI](../api/) listen inside the pod
only, so add `[api] listen = "0.0.0.0:8053"` and a token hash there, then reach them with
`kubectl port-forward`. The chart deploys one node: not the cluster or the witness of
[High availability](../ha/). On Kubernetes those need a shape of their own, so until it exists,
use the Compose files or the packages there.

### From source

Install Rust with [rustup](https://rustup.rs), a C compiler (`build-essential` on Debian and
Ubuntu, `gcc` elsewhere) and Node.js 24 or later (for the web UI only), then:

```sh
git clone https://github.com/nxplain-sh/goethite && cd goethite
(cd web && npm ci --ignore-scripts && npm run build)
cargo build --release --locked
```

The binary is `target/release/goethite`. It has no runtime dependencies beyond the C library;
Node.js is needed only to build. Skip the `web` line to build without the web UI. Install it as
for the tarball, with `target/release/goethite`, `deploy/systemd/goethite.service` and
`deploy/goethite.toml`. `cargo xtask dist` builds the release files themselves, in the pinned
build image (it needs docker or podman).

## Configure

The installed config listens on port 53 on every address, forwards to Quad9 over DNS over TLS,
and keeps its data in `/var/lib/goethite`. New nodes start with a recommended set of filter
lists. Change the `[[upstream]]` tables to use another resolver; the
[configuration reference](../configuration/) lists every setting. Check the result before
starting:

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

With a package, install the new one: `sudo apt install ./goethite_<new version>_<arch>.deb` or
`sudo dnf install ./goethite-<new version>.<arch>.rpm`. The package asks the running goethite to
hand over to the new binary, as below, and keeps your config.

Otherwise, install the new binary and ask the running goethite to hand over to it:

```sh
sudo install -m 0755 goethite /usr/bin/goethite
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

Not sure whether a newer release exists? The web UI's Settings page has **Check for updates**: it
asks GitHub for the newest release and says whether this node runs it. It installs nothing; the
upgrade stays yours to start, as above.

Read the [changelog](../changelog/) first: before 1.0, a minor version may change the
configuration format, and `goethite check-config` tells you what to fix.
