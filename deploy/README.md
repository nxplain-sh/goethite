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
| [`container/`](container/)                                       | The container image (its Containerfile and config) and a Compose file that runs one node unprivileged from the start |
| [`container/cluster/`](container/cluster/)                       | Compose files and example configs for a cluster: `node/` for each DNS node with its floating IP, `witness/` for the witness |
| [`helm/goethite/`](helm/goethite/)                               | The Helm chart for Kubernetes: one node, unprivileged by default, the store and the downloaded lists on a PersistentVolumeClaim |

CI checks `goethite.service` and `goethite-witness.service` with `systemd-analyze verify`. `systemd-analyze security <unit>`
reviews either sandbox on a host. CI lints the Helm chart and renders both shapes it runs in
(`helm lint`, `helm template`). `cargo xtask dist` builds the packages and `cargo xtask image`
the container image ([ADR 0027](../docs/adr/0027-packages-and-container-image.md),
[ADR 0036](../docs/adr/0036-compose-files.md), [ADR 0037](../docs/adr/0037-helm-chart.md));
`tests/packages/install.sh` installs the packages on each supported distribution.

What does not belong here: build automation (that is [`xtask/`](../xtask/) and
[`.github/workflows/`](../.github/workflows/)) and secrets. A unit may point at a token file; it
never contains one.
