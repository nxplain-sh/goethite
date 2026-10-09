---
title: High availability
description: Run two goethite nodes that share one configuration and one floating IP.
---

Two goethite nodes can form a cluster. Each answers DNS on its own, so either one can serve your
network, and they share one filtering configuration: lists, rules, groups, clients, schedules and
settings.

- The **primary** owns the configuration.
- The **replica** copies the primary's configuration within moments of every change. If the
  primary is unreachable, the replica keeps filtering with its last copy and tries again, with
  pauses growing to 30 seconds.

You can make changes through either node: the replica hands them to the primary (see below).

The nodes talk over their own port (8054 by default) with mutual TLS: each node proves who it is
with a certificate from the cluster's private CA, and accepts only the peer it is configured
with.

## Certificates

On any machine with goethite, create the cluster's CA and a certificate for each node:

```sh
mkdir cluster && cd cluster
goethite cluster init
goethite cluster cert dns1
goethite cluster cert dns2
```

This gives `ca.crt` and `ca.key`, plus `dns1.crt`, `dns1.key`, `dns2.crt` and `dns2.key`. Node
names are 1 to 63 lowercase letters, digits and hyphens, starting with a letter. Keys are created
readable by their owner only, and existing files are never overwritten (`--force` replaces a
node's certificate).

Copy `ca.crt` and each node's own certificate and key to that node, for example into
`/etc/goethite/cluster/`. `ca.key` is only needed to issue certificates: keep it somewhere safe,
off the nodes. Certificates are valid for 10 years.

## Configuration

On the primary, `dns1` at 192.0.2.11:

```toml
[cluster]
node = "dns1"
role = "primary"
listen = "192.0.2.11:8054"
ca = "/etc/goethite/cluster/ca.crt"
cert = "/etc/goethite/cluster/dns1.crt"
key = "/etc/goethite/cluster/dns1.key"

[cluster.peer]
node = "dns2"
address = "192.0.2.12:8054"
```

On the replica, `dns2`, the same with the names and addresses swapped and `role = "replica"`.
Restart both. The replica logs `copied the primary's configuration`, and from then on follows
every change. Its audit log records each copy as `replicate` by `replication` from `dns1`.

Everything outside the store stays per node: the `[server]`, `[[upstream]]`, `[cache]`,
`[security]`, `[querylog]` and `[api]` tables, the query log, statistics and pausing. Each node
downloads filter lists itself, so lists given by `path` must exist on both.

Run the same goethite version on both nodes: a replica refuses a configuration from another
store schema and says so in its log.

## Changing the configuration

Through the primary, changes work as on a node of its own. Through the replica, a change to lists,
rules, groups, clients, schedules or settings is forwarded to the primary with your identity, and
answered with the primary's answer once the replica has copied it, so reading it back right away
works. `If-Match` revisions mean the same on both nodes. The primary's audit log records you as
the caller, with `"node": "dns2"` for the replica it came through.

Pausing filtering and downloading lists act on the node you ask, not the cluster.

While the replica cannot reach the primary, changes through it are refused with
`503 unavailable` and a message saying so. Everything else keeps working.

## Cluster status

Each node reports the cluster at `GET /api/v1/cluster`, and in `cluster` of
`GET /api/v1/status`:

```json
{
  "node": "dns2",
  "role": "replica",
  "config": { "epoch": 234708808564767, "version": 6 },
  "writable": true,
  "peer": {
    "node": "dns1", "address": "192.0.2.11:8054", "reachable": true,
    "role": "primary", "version": "0.3.0", "config": { "epoch": 234708808564767, "version": 6 }
  },
  "sync": { "last_contact": "2026-10-08T09:30:01Z", "last_copy": "2026-10-08T09:29:15Z" },
  "problems": []
}
```

Nodes check on each other every 5 seconds. `problems` lists, in words, anything that needs a
person: both nodes primary (or both replicas), different goethite versions, or a replica that
cannot copy the primary's configuration.

## Statistics

Each node keeps its own query log and statistics. `GET /api/v1/stats?scope=cluster` adds up
both nodes' counts, hour by hour, and merges their top lists. `nodes` names the nodes included;
a node that could not be asked is named in `unreachable` instead of being silently left out. The
TUI and the web UI show the cluster's statistics, and the cluster's state, on their dashboards.
Each node's top lists are approximate, and so are the merged ones.

## Promoting the replica

If the primary is gone for good, or for longer than you want the configuration frozen, make the
replica the primary:

```sh
curl -X POST http://127.0.0.1:8053/api/v1/cluster/promote
```

Its configuration becomes the cluster's from then on, in a new epoch. goethite refuses while the
current primary is reachable: demote it first (`POST /api/v1/cluster/demote` on it), or pass
`{"force": true}`. The new role survives restarts, until you edit `role` in the config file.

When the old primary comes back, it is still primary, and both nodes report the problem. Demote
it:

```sh
curl -X POST http://dns1:8053/api/v1/cluster/demote
```

It becomes a replica and copies the new primary's configuration, replacing its own. Changes made
on it while the two were apart are lost, which is why both nodes warn as long as two primaries
exist. A demote is refused unless the other node is a reachable primary (`force` overrides).

## A floating IP

Many clients use only their first DNS server, or wait seconds before trying the second. A
floating IP gives them one address that whichever node is healthy holds. `goethite vrrp` moves it
between the nodes with VRRP version 3 (RFC 5798), the protocol routers use for the same job. It
runs beside the DNS server on each node:

- once a second it asks its own node for `health.goethite.test`, which goethite answers itself
  and leaves out of the query log;
- the healthy node with the higher priority holds the address and says so once a second;
- after three failed health checks in a row, a node hands the address over at once. After two
  good ones, it can hold the address again;
- when the holder falls silent, the other node takes over within 3.6 seconds and announces the
  move with gratuitous ARP, so switches and clients follow straight away.

The floating IP has nothing to do with which node is primary: either node can hold it, with or
without a `[cluster]` table. Both nodes must be on the same network segment, since VRRP and ARP
do not cross routers.

### Setting it up

On `dns1` at 192.0.2.11, with the floating IP 192.0.2.53:

```toml
[server]
# The floating IP, and an address that is always there for the health check.
listen = ["192.0.2.53:53", "127.0.0.1:53"]

[vrrp]
interface = "eth0"
address = "192.0.2.53"
peer = "192.0.2.12"
router_id = 53
priority = 150
```

On `dns2`, the same with `peer = "192.0.2.11"` and a lower priority, such as `100`. goethite
listens on the floating IP even while the other node holds it, and answers on it as soon as it
arrives. All the settings are in the [configuration reference](../configuration/#vrrp).

Then install
[`deploy/systemd/goethite-vrrp.service`](https://github.com/nxplain-sh/goethite/blob/main/deploy/systemd/goethite-vrrp.service)
beside `goethite.service` on both nodes:

```sh
sudo install -m 0644 deploy/systemd/goethite-vrrp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart goethite
sudo systemctl enable --now goethite-vrrp
```

It is a separate service so the DNS server never holds what it needs: `CAP_NET_RAW` for its raw
sockets, which it gives up once they are open, and `CAP_NET_ADMIN` to add and remove the address.
Its log says what it does:

```
INFO goethite answers its health checks; standing by as backup
INFO the peer is silent or has lower priority; taking over
INFO this node holds the floating IP now address=192.0.2.53 interface=eth0
```

`ip -4 addr show eth0` lists the floating IP on the node that holds it. Hand it out as the DNS
server in your DHCP settings.

### How fast it moves

With the default one-second interval, measured between Linux network namespaces:

| What happens on the node holding the address | The other node holds it after |
| --- | --- |
| `goethite-vrrp` stops, or `goethite` stops (which stops it too) | 0.7 s: it hands over at once |
| goethite stops answering | about 3 s: three failed health checks |
| The node fails, or is cut off | 3.6 s: three missed announcements, plus a little |

When the node with the higher priority is healthy again, it takes the address back after about
5 seconds. Set `preempt = false` on both nodes to leave it where it is instead, saving a second
move. A lower `interval_ms` makes everything faster, at the risk of a busy network delaying
announcements enough to move the address for nothing.

### Networks without multicast

VRRP announces itself to the multicast group 224.0.0.18. Some virtual switches and Wi-Fi bridges
drop multicast: then both nodes take the address. Set `unicast = true` on both nodes to send the
announcements straight to the peer.

### Security

VRRP has no authentication: version 3 dropped it, since a password sent in the clear protected
nothing. goethite accepts announcements only from the configured `peer`, only from the same
network segment (with a TTL of 255), and only for the configured `router_id` and address. Any
host on that segment can still forge an announcement and take the address, just as it could take
any address there with forged ARP. Run the floating IP on a network you trust, and give it a
`router_id` no other VRRP pair on the network uses.

## Upgrading the pair

Upgrade one node at a time, as in [Upgrade](../install/#upgrade): the handover drops no query,
and the floating IP stays where it is. Upgrade the replica first. While the two versions differ,
both nodes report it in `problems`, and a replica refuses a configuration from another store
schema until it runs the same version.

`goethite vrrp` runs the old binary until it restarts. `sudo systemctl restart goethite-vrrp`
hands the floating IP to the other node and, with `preempt`, takes it back about 5 seconds
later. A query sent at the moment of a move can go unanswered and be retried by the client, so
restart it when that does not matter, or on the node that does not hold the address.

## When something fails

| What happens | What goethite does |
| --- | --- |
| The primary goes down | The replica keeps answering with its last copy, logs once that it cannot reach the primary, refuses configuration changes, and copies again as soon as the primary is back. Promote the replica to change the configuration meanwhile. |
| The replica goes down | Nothing changes on the primary. The replica copies the latest configuration when it starts. |
| The network between them fails | Both keep answering. Changes on the primary reach the replica when the network is back. If the nodes cannot hear each other's VRRP announcements, both take the floating IP until the network is back. |
| The node holding the floating IP fails | The other node takes the address within 3.6 seconds, and clients keep using it. |
| `goethite vrrp` crashes on the node holding the address | The other node takes over within 3.6 seconds. The crashed one's copy of the address stays until systemd restarts it, 2 seconds later, and it removes the copy first thing. |

The cluster network carries configuration only. Keep it private anyway, and allow the cluster
port only between the two nodes.
