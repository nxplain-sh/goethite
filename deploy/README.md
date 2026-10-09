# `deploy/`

How a built goethite is installed and run on a host. Each file explains itself in its header
comment; the install steps are in the [install guide](../site/src/content/docs/install.md) and,
for the floating IP, the [HA guide](../site/src/content/docs/ha.md).

| File                                                           | What it runs                                                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| [`systemd/goethite.service`](systemd/goethite.service)           | The DNS server, as a dynamic user that gives up `CAP_NET_BIND_SERVICE` once bound, in a read-only sandbox     |
| [`systemd/goethite-vrrp.service`](systemd/goethite-vrrp.service) | The floating-IP helper, a separate service so the DNS server never holds `CAP_NET_RAW` or `CAP_NET_ADMIN` |

CI checks `goethite.service` with `systemd-analyze verify`. `systemd-analyze security <unit>`
reviews either sandbox on a host.

What does not belong here: build automation (that is [`xtask/`](../xtask/) and
[`.github/workflows/`](../.github/workflows/)) and secrets. A unit may point at a token file; it
never contains one.
