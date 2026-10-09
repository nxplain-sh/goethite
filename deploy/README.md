# `deploy/`

How a built goethite is installed and run on a host. Each file explains itself in its header
comment; the install steps are in the [install guide](../site/src/content/docs/install.md) and,
for the floating IP, the [HA guide](../site/src/content/docs/ha.md).

| File                                                             | What it is                                                                                                    |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| [`systemd/goethite.service`](systemd/goethite.service)           | The DNS server, as a dynamic user that gives up `CAP_NET_BIND_SERVICE` once bound, in a read-only sandbox     |
| [`systemd/goethite-vrrp.service`](systemd/goethite-vrrp.service) | The floating-IP helper, a separate service so the DNS server never holds `CAP_NET_RAW` or `CAP_NET_ADMIN`     |
| [`systemd/goethite-witness.service`](systemd/goethite-witness.service) | A cluster witness on a third machine: votes, never leads, serves no DNS; no privileges at all            |
| [`goethite.toml`](goethite.toml)                                 | The server config the packages and the tarball install as `/etc/goethite/goethite.toml`                       |
| [`package/`](package/)                                           | The .deb and .rpm packages: nfpm's description, the install and removal scripts, the Debian copyright file    |
| [`container/`](container/)                                       | The container image: its Containerfile and config                                                             |

CI checks `goethite.service` and `goethite-witness.service` with `systemd-analyze verify`. `systemd-analyze security <unit>`
reviews either sandbox on a host. `cargo xtask dist` builds the packages and `cargo xtask image`
the container image ([ADR 0027](../docs/adr/0027-packages-and-container-image.md));
`tests/packages/install.sh` installs the packages on each supported distribution.

What does not belong here: build automation (that is [`xtask/`](../xtask/) and
[`.github/workflows/`](../.github/workflows/)) and secrets. A unit may point at a token file; it
never contains one.
