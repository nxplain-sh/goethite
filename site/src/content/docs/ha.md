---
title: High availability
description: Run two goethite nodes that share one configuration.
---

Two goethite nodes can form a cluster. Each answers DNS on its own, so either one can serve your
network, and they share one filtering configuration: lists, rules, groups, clients, schedules and
settings.

- The **primary** owns the configuration. Make changes there, through its API, TUI or web UI.
- The **replica** copies the primary's configuration within moments of every change. If the
  primary is unreachable, the replica keeps filtering with its last copy and tries again, with
  pauses growing to 30 seconds.

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

## When something fails

| What happens | What goethite does |
| --- | --- |
| The primary goes down | The replica keeps answering with its last copy, logs once that it cannot reach the primary, and copies again as soon as it is back. |
| The replica goes down | Nothing changes on the primary. The replica copies the latest configuration when it starts. |
| The network between them fails | Both keep answering. Changes on the primary reach the replica when the network is back. |

The cluster network carries configuration only. Keep it private anyway, and allow the cluster
port only between the two nodes.
