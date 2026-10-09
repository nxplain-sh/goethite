---
title: High availability
description: Run goethite nodes that share one configuration, a witness, and a floating IP.
---

goethite nodes can form a cluster. Each answers DNS on its own, so any one of them can serve your
network, and they share one filtering configuration: lists, rules, local records, groups, clients,
schedules and settings.

The members agree on every change with [Raft](https://raft.github.io/). One member **leads**:
changes are made through it, and every member applies them in the same order. You can make
changes through any member: the others hand them to the leader (see below). If the leader is
lost, the others elect a new one within seconds, as long as most of the voters can
still reach each other: in the [chaos lab](https://github.com/nxplain-sh/goethite/tree/main/tests/chaos),
about 5 seconds after the leader crashed, and about 12 when it was cut off but still running
(the others first wait until it can no longer claim to lead). DNS does not wait for any of this.

- **Two nodes and a witness** is the setup to aim for. A witness (`goethite witness`) votes but
  never leads, and serves no DNS and no API, so it runs on anything small: a router, a NAS, a
  container. With it, losing any one of the three keeps changes working.
- **Two nodes alone** work as goethite 0.4's primary and replica did: one votes, the other
  follows. If the voter is lost, the configuration is frozen until the other takes the cluster
  over.
- **Three or more nodes** need no witness.

A member that cannot reach the cluster keeps filtering with the configuration it has; DNS never
waits for the cluster.

The members talk over their own port (8054 by default) with mutual TLS: each proves who it is
with a certificate from the cluster's private CA, and accepts only the members it knows.

## Certificates

On any machine with goethite, create the cluster's CA and a certificate for each member:

```sh
mkdir cluster && cd cluster
goethite cluster init
goethite cluster cert dns1
goethite cluster cert dns2
goethite cluster cert witness
```

This gives `ca.crt` and `ca.key`, plus a `.crt` and a `.key` for each member. Names are 1 to 63
lowercase letters, digits and hyphens, starting with a letter. Keys are created readable by their
owner only, and existing files are never overwritten (`--force` replaces a member's certificate).

Copy `ca.crt` and each member's own certificate and key to that member, for example into
`/etc/goethite/cluster/`. `ca.key` is only needed to issue certificates: keep it somewhere safe,
off the members. Certificates are valid for 10 years.

## Configuration

On `dns1`, at 192.0.2.11, which starts the cluster:

```toml
[cluster]
node = "dns1"
bootstrap = true
listen = "192.0.2.11:8054"
ca = "/etc/goethite/cluster/ca.crt"
cert = "/etc/goethite/cluster/dns1.crt"
key = "/etc/goethite/cluster/dns1.key"

[[cluster.member]]
node = "dns2"
address = "192.0.2.12:8054"

[[cluster.member]]
node = "witness"
address = "192.0.2.13:8054"
```

On `dns2`, the same without `bootstrap`, with its own name, address and files, and `dns1` and the
witness as members. Each member lists the others. `listen` is also the address the others reach
a member on, so give a member's own address rather than `0.0.0.0` where you can.

`bootstrap = true` goes on one node only: when that node is in no cluster yet, it starts one, with
its own configuration. The other members wait to be added. Every few seconds the leader adds each
member in its config file that answers and runs the same goethite version, then makes them
voters once they have caught up and that makes three voters or more. (Two voters would be worse
than one: losing either would stop all changes.) Restart all of them; `dns1` logs `started the
cluster`, and the others take the cluster's configuration, replacing their own.

Everything outside the store stays per node: the `[server]`, `[[upstream]]`, `[cache]`,
`[security]`, `[querylog]` and `[api]` tables, the query log, statistics and pausing. Each node
downloads filter lists itself, so lists given by `path` must exist on every node.

Run the same goethite version on every member: while one runs another, the leader refuses
configuration changes, and says why.

### A witness

On the witness, at 192.0.2.13, install goethite as on any node, then give
`/etc/goethite/goethite.toml` only a `[cluster]` table (and `[store]`, if not the default path):

```toml
[cluster]
node = "witness"
listen = "192.0.2.13:8054"
ca = "/etc/goethite/cluster/ca.crt"
cert = "/etc/goethite/cluster/witness.crt"
key = "/etc/goethite/cluster/witness.key"

[[cluster.member]]
node = "dns1"
address = "192.0.2.11:8054"

[[cluster.member]]
node = "dns2"
address = "192.0.2.12:8054"
```

and run `goethite witness` instead of `goethite run`. The packages install a hardened
`goethite-witness.service` for it (from a tarball, it is in its `systemd/` directory):

```sh
sudo systemctl enable --now goethite-witness
```

It needs no upstreams, no privileges and no port below 1024. It keeps the cluster's log and
configuration in its store like every member, which makes it a third copy, and logs the
cluster's leader as it changes:

```
INFO starting goethite witness version=0.5.0
INFO the cluster's leader leader=dns1 term=1
```

### From goethite 0.4

goethite 0.4's tables keep working. On the node whose `role` is `"primary"` (or that `promote`
made primary), the cluster starts with its configuration; the node with `role = "replica"` waits
to be added; `[cluster.peer]` counts as one `[[cluster.member]]`. Upgrade both nodes, then add a
witness to both config files when you are ready. Configuration changes are refused while the two
run different versions.

## Changing the configuration

Through the leader, changes work as on a node of its own. Through any other member, a change to
lists, rules, local records, groups, clients, schedules or settings is forwarded to the leader
with your identity, and answered with the leader's answer once the member has applied it, so
reading it back right away works. `If-Match` revisions mean the same on every member. Every
member's audit log records the change with you as the caller, and `"node": "dns2"` for the member
it came through.

Pausing filtering and downloading lists act on the node you ask, not the cluster.

While a member cannot reach a leader, changes through it are refused with `503 unavailable` and
a message saying why. Everything else keeps working.

## Cluster status

Each node reports the cluster at `GET /api/v1/cluster`, and in `cluster` of
`GET /api/v1/status`:

```json
{
  "node": "dns2",
  "role": "replica",
  "state": "follower",
  "cluster": "8f1c2e40a7b3d915",
  "leader": "dns1",
  "term": 1,
  "config": { "epoch": 234708808564767, "version": 6 },
  "writable": true,
  "members": [
    { "node": "dns2", "address": "192.0.2.12:8054", "this_node": true, "membership": "voter",
      "witness": false, "reachable": true, "state": "follower", "version": "0.5.0" },
    { "node": "dns1", "address": "192.0.2.11:8054", "this_node": false, "membership": "voter",
      "witness": false, "reachable": true, "state": "leader", "version": "0.5.0" },
    { "node": "witness", "address": "192.0.2.13:8054", "this_node": false, "membership": "voter",
      "witness": true, "reachable": true, "state": "follower", "version": "0.5.0" }
  ],
  "peer": { "node": "dns1", "address": "192.0.2.11:8054", "reachable": true, "role": "primary" },
  "sync": { "last_contact": "2026-10-09T09:30:01Z", "last_copy": "2026-10-09T09:29:15Z" },
  "problems": []
}
```

`state` is `leader`, `follower` (a voter), `learner` (receives every change but does not vote,
or waits to be added), `candidate` (an election is on) or `stopped`. `membership` says whether a
member votes, learns, or is only in this node's config file so far. On the leader, `matched` is
the last log entry each member is known to hold. `role` and `peer` are goethite 0.4's view, kept
for scripts written against it: the leader is the `primary`.

Members check on each other every 5 seconds. `problems` lists, in words, anything that needs a
person: no leader, a member that is unreachable, runs another version or is in another cluster,
or two voters. The web UI and the TUI show the cluster on their dashboards.

## Statistics

Each node keeps its own query log and statistics. `GET /api/v1/stats?scope=cluster` adds up every
node's counts, hour by hour, and merges their top lists. `nodes` names the nodes included; a node
that could not be asked is named in `unreachable` instead of being silently left out. Witnesses
answer no DNS and have none. Each node's top lists are approximate, and so are the merged ones.

## When the cluster cannot elect a leader

With a witness, or three nodes, this takes losing most of the voters. With two nodes alone, it
takes losing the one that votes. If the lost voters are gone for good, or for longer than you
want the configuration frozen, take the cluster over on a member that is left:

```sh
curl -X POST http://127.0.0.1:8053/api/v1/cluster/promote
```

It leaves its cluster and starts a new one, as its only voter, with its own configuration.
goethite refuses while a leader of the cluster answers, since there is nothing to take over (pass
`{"force": true}` to do it anyway). The new cluster has a new ID; its leader adds the members in
its config file as they join.

A member that comes back still belongs to the old cluster, and both clusters report each other
in `problems`. Make it join the new one:

```sh
curl -X POST http://dns1:8053/api/v1/cluster/demote
```

It leaves its old cluster, and the new cluster's leader adds it, replacing its configuration.
A demote is refused unless the leader of another cluster answers (`force` overrides).

## Removing a member

To take a member out of service for good, remove it from every member's config file and restart
the members one at a time (the config file is read when goethite starts; `systemctl kill
--signal=SIGUSR2 --kill-whom=main goethite` restarts one in place without dropping a query),
then:

```sh
curl -X DELETE http://127.0.0.1:8053/api/v1/cluster/members/dns3
```

Any member forwards it to the leader. If that leaves two voters, the leader goes back to voting
alone. Certificates cannot be revoked: to lock a removed member out for good, create a new CA and
issue new certificates to the remaining members.

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

Then start `goethite-vrrp.service` beside `goethite.service` on both nodes. The packages install
it; from a tarball, install it from the `systemd/` directory first (it is in
[`deploy/systemd/`](https://github.com/nxplain-sh/goethite/blob/main/deploy/systemd/goethite-vrrp.service)
in the repository):

```sh
sudo install -m 0644 systemd/goethite-vrrp.service /etc/systemd/system/   # tarball only
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

## Upgrading

Upgrade one member at a time, as in [Upgrade](../install/#upgrade): the handover drops no query,
and the floating IP stays where it is. Configuration changes are refused until every member runs
the same version. The packages restart a running witness when they upgrade it.

`goethite vrrp` runs the old binary until it restarts. `sudo systemctl restart goethite-vrrp`
hands the floating IP to the other node and, with `preempt`, takes it back about 5 seconds
later. A query sent at the moment of a move can go unanswered and be retried by the client, so
restart it when that does not matter, or on the node that does not hold the address.

## When something fails

| What happens | What goethite does |
| --- | --- |
| The leader goes down | With a witness (or three nodes), the others elect a new leader within seconds (about 5 in the chaos lab), and changes go on. With two nodes alone, the other keeps answering with its configuration, refuses changes and says so; it follows again when the leader is back. Take the cluster over to change the configuration meanwhile. |
| A follower or the witness goes down | Nothing changes for the rest, as long as most voters remain. A member catches up when it is back. |
| The network splits | Every member keeps answering. The side with most of the voters keeps a leader and takes changes; the other side refuses them, and catches up when the network is back. If the nodes cannot hear each other's VRRP announcements, both take the floating IP until the network is back. |
| The node holding the floating IP fails | The other node takes the address within 3.6 seconds, and clients keep using it. |
| `goethite vrrp` crashes on the node holding the address | The other node takes over within 3.6 seconds. The crashed one's copy of the address stays until systemd restarts it, 2 seconds later, and it removes the copy first thing. |

The cluster network carries configuration only. Keep it private anyway, and allow the cluster
port only between the members.
