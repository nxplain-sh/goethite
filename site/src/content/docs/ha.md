---
title: High availability
description: Run two goethite nodes that share one configuration.
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

## When something fails

| What happens | What goethite does |
| --- | --- |
| The primary goes down | The replica keeps answering with its last copy, logs once that it cannot reach the primary, refuses configuration changes, and copies again as soon as the primary is back. Promote the replica to change the configuration meanwhile. |
| The replica goes down | Nothing changes on the primary. The replica copies the latest configuration when it starts. |
| The network between them fails | Both keep answering. Changes on the primary reach the replica when the network is back. |

The cluster network carries configuration only. Keep it private anyway, and allow the cluster
port only between the two nodes.
