# ADR 0031: Raft for the cluster's configuration, with a witness

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

Phase 3 made goethite highly available with two nodes, a primary and a replica
([ADR 0010](0010-cluster-config-sync.md)). The replica copied whole configuration snapshots
from the primary. That model has two limits the roadmap names for v0.5:

- **No automatic failover for writes.** When the primary is lost, the configuration is frozen
  until someone promotes the replica. A promotion during a partition makes two primaries, and
  the changes on one of them are lost when it is demoted.
- **Two nodes only.** There is no way to add a third node, and no way to tell a dead primary
  from an unreachable one.

DNS itself is not at stake: every node answers on its own with the configuration it has, and
that must stay true. What is at stake is changing the configuration safely while nodes fail.

The approved plan for v0.5 is Raft through openraft 0.9 (the stable line), with a vote-only
witness so that two goethite nodes plus something small survive the loss of any one of them.
The cluster channel (mutual TLS with node certificates from a private CA, B5 in the
[threat model](../THREAT_MODEL.md)) stays.

## Decision

**The members of a cluster agree on one log of configuration changes with Raft, and every member
applies it to its own store. One member leads: changes are made through it; the others forward
theirs to it, as a replica did.**

**The store is the state machine.** A change made through the API is prepared on the leader as
before (the closure that edits a copy of the configuration, then validation), but instead of
writing it, the store hands a `Change` to the cluster: the rows it writes (whole resources, by
kind and ID, or deletions, or the settings), its audit entries, its time and actor, and the
configuration version it was prepared against. Every member applies the log's entries in order
with `Store::apply`: a change applies only to the version it was prepared against, so it is
applied, or refused, on every node alike, and a stale one becomes a conflict for its caller
("make it again"). The rows, the audit entries, the new version and a note of the log entry
(index, term, membership) are written in one redb transaction, so the configuration and what it
includes never disagree. The audit log thus holds the same entries, with the original actor, on
every member. Entries that change nothing (membership, Raft's own blank entries) only advance the
note. Audit entries that change no configuration, such as pausing filtering, stay local.

**The log lives in the store.** Entries are JSON in a `cluster_log` table, the vote and the
committed and purged positions in `meta` under `cluster_` keys, all written durably before Raft
is told (the store's calls run on blocking threads). A snapshot is the whole configuration
(`ConfigExport`) taken on demand, since the configuration is small and always on disk; its ID
is the node and the log position, so the same position on the same node is the same bytes.
Snapshots are taken every 500 entries, keeping 100 after them; they install with the same
diff-and-write path a replica used. openraft's own storage test suite runs against it.

**Seeding.** The first entry after the membership is a `Seed`: the whole configuration of the
node the cluster starts on, in a new epoch. A node joining a cluster takes the seed (or a
snapshot) and so the cluster's configuration, replacing its own, as a replica did.

**Membership comes from the config file, through the leader.** `[cluster] bootstrap = true` on
one node starts a cluster there, as its only voter, if the node is in none and never left one.
`[[cluster.member]]` tables list the other members. Every five seconds each node asks every
member it knows (config file and Raft membership) how it is, and the leader:

- adds every listed member that answers, runs the same goethite version and is in no other
  cluster, as a learner (it receives the log but does not vote);
- follows a member to a new address, once the member answers there;
- makes every learner that is within 16 entries of the log a voter, once that makes **three
  voters or more**. Two voters would be worse than one: losing either stops all changes. So two
  nodes alone keep one voter and one learner, which is the primary and replica of goethite 0.4
  under another name, and a third member makes them all voters.

Members are removed only by `DELETE /api/v1/cluster/members/{node}`, refused while the member is
still in the leader's config file (it would be added again). A Raft node ID is FNV-1a of the
node's name, so every node computes the same one; configurations with two names that hash alike
are refused.

**The witness** is `goethite witness`: Raft, a store and the cluster listener, without DNS, an
API or a filter. It is a voter like any other, with openraft's elections turned off
(`enable_elect = false`): it votes but never stands, so it never needs to run API changes. It
keeps the log and the configuration like every member, so its store is also a third copy.

**Clusters are tagged.** Starting a cluster picks a random 64-bit cluster ID, kept in the store;
every Raft message carries it, and a member refuses messages from another cluster. A node in no
cluster yet joins the cluster of the first leader that sends it entries (it never votes before
that). Taking over and leaving (below) change or forget the ID, so the logs of two clusters never
mix.

**Failure handling.** With two nodes and a witness, losing any one keeps a majority: a new leader
is elected within seconds (heartbeats every 500 ms, elections after 1.5 to 3 s of
silence; a LAN with room to spare) and changes go on. Voters refuse other candidates for 3 s after
they last heard a leader (openraft's lease, the longest election timeout), and a candidate that
learns another member holds a longer log waits 6 s more: the chaos lab measured about 5 s after
the leader crashed, and about 12 s when it was cut off but still running. Without a majority, changes are refused
with `503` and a reason; DNS is untouched. For a cluster that cannot elect a leader and will not
again soon (two nodes without a witness that lost the voter), `POST /api/v1/cluster/promote`
takes it over: the node leaves its cluster and starts a new one as its only voter, with its own
configuration, refused while a leader of its cluster answers unless forced. When the other node
returns, both report the other cluster, and `POST /api/v1/cluster/demote` on it makes it leave
its cluster and join the new one, whose leader then replaces its configuration.

**API.** `GET /api/v1/cluster` keeps every field it had: `role` is `primary` on the leader and
`replica` elsewhere, `peer` is the leader (or, on the leader, another member) and `sync` reports
following the leader. It gains `state`, `cluster`, `leader`, `term` and `members` (each with its
membership, witness flag, reachability, version and, on the leader, how far its log reaches).
`promote` and `demote` keep their names with the meanings above. Configuration changes and member
removal are forwarded to the leader with the caller's identity; the leader names the forwarding
member from its TLS client certificate. Every member must run the same goethite version: the
leader refuses changes while one does not, and a member that cannot apply an entry (another
schema, an unknown kind of resource) stops Raft rather than drift, and says so.

**Upgrading from 0.4.** The old tables still work: `role = "primary"` (or the role promote and
demote left in the store) starts the cluster with that node's configuration, `role = "replica"`
waits to be added, and `[cluster.peer]` is one `[[cluster.member]]`. The two-node behaviour is
the same as before, except that a promotion makes a new cluster that the old primary joins once
demoted, instead of two primaries.

**Bounds.** At most 15 other members in a config file; Raft messages up to 256 MiB (a seed holds
a whole configuration), snapshots up to 512 MiB, sent in 1 MiB pieces; 64 entries per message;
changes time out after 10 s; 32 cluster connections at once. A node whose store fell back to
memory does not join the cluster: forgetting the log would let it undo agreed changes.

## Alternatives considered

- **Keep primary and replica.** Simple and already shipped, but every failover needs a person,
  and a promotion during a partition loses changes. The roadmap asks for more.
- **Raft without a witness.** Two voters cannot lose either. Three goethite nodes work too (and
  are supported), but many home and small-office networks have two machines for DNS and a third
  that should not run it.
- **A witness that stores nothing.** Raft voters must keep the log to vote safely; a witness
  without it could elect a leader missing committed changes. The configuration is small, so the
  witness keeps everything and is a third copy for free.
- **Log entries as the API requests that made them, replayed everywhere.** Every node would run
  the change logic, so IDs, times and validation would have to be deterministic everywhere, and a
  bug would diverge silently. Shipping the resulting rows keeps the logic on the leader and makes
  applying trivial and checkable.
- **openraft 0.10.** It has leadership transfer and other improvements, but is not released as
  stable. 0.9's storage traits (with `storage-v2`) are enough; moving later is a contained change
  in `goethite-cluster::raft`.
- **etcd, Consul or another external store.** Another service to run, secure and upgrade, and
  the data plane would depend on it at startup. Rejected, as in ADR 0006.

## Consequences

- Two nodes and a witness (or three nodes) fail over by themselves; two nodes alone behave as
  before. The cost of a change is one more round trip and two more fsyncs (log and state machine)
  per member, irrelevant at configuration rates.
- A new dependency, openraft (MIT OR Apache-2.0), with its own dependencies; it passes
  `cargo-deny`. Duplicate versions of a few small crates come with it.
- The audit log now holds the same configuration changes on every member, by their real actors;
  local actions stay local.
- Mixed versions cannot change the configuration until the upgrade is finished, and a node that
  cannot apply an entry stops following until it runs the same version.
- Timeouts suit a LAN. A WAN between members may need longer ones; they are constants for now.
- One TLS connection per Raft message (with session resumption): simple and robust, at the cost
  of a handshake twice a second per follower. Keep-alive connections are a later optimization.
- Revisit when openraft 0.10 is stable (leadership transfer would let `promote` move leadership
  inside a healthy cluster instead of refusing).
