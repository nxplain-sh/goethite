# ADR 0010: Two-node configuration sync

- **Status:** Superseded by [ADR 0031](0031-raft-clustering.md)
- **Date:** 2026-10-08

## Context

Phase 3 makes goethite highly available with two nodes. Both must filter the same way, so the
configuration in the store ([ADR 0006](0006-config-store.md)) has to be the same on both. The
architecture principles set the bounds:

- Every node answers DNS fully on its own. Losing the cluster layer must never break resolution.
- The replicated store is the single source of truth, edited through the API.
- Raft (via openraft) is planned for 1.0. Phase 3 needs something simpler that does not paint us
  into a corner.

## Decision

**Primary and replica.** One node is the primary: configuration changes happen there. The other
is a replica that copies the primary's configuration. A node's role comes from its `[cluster]`
table, or from `POST /api/v1/cluster/promote` and `/demote`. A role changed that way is kept in
the store and survives restarts, until the config file's `role` itself changes. Promotion starts
a new epoch. It is refused while the other node is a reachable primary, and a demotion is
refused unless it is, unless forced, so two primaries arise only by force or a partition. Both
nodes then report it.

**Forwarding.** A configuration change made through the replica's API (a `POST`, `PUT` or
`DELETE` of lists, rules, groups, clients, schedules or settings) is forwarded over the cluster
channel to `/cluster/v1/api` on the primary. The body travels as sent, with the caller's
authenticated identity. The primary runs it through its own routes as that caller, marked with
the replica's node name: an in-process extension no HTTP client can set takes the place of
authentication. The replica returns the primary's answer, byte for byte, after waiting (at most
3 s) until it has copied the resulting version, so callers read their own writes. While a
heartbeat (every 5 s) says the primary is unreachable, such changes are refused with 503;
everything else, including pausing and list downloads, stays local.

**Whole snapshots, versioned.** Every store change that writes resources bumps a
`ConfigVersion { epoch, version }`, in the same transaction. The *epoch* is random. It is chosen
when a store is created, and again when a node becomes primary. It names a line of history; the
*version* counts changes along it. A replica takes a configuration whose epoch differs from its
own, or whose version is newer. That one rule covers the first copy, normal changes, a primary
whose store was rebuilt, and a promoted replica. Nothing older is ever applied.

The replica receives the whole configuration, not a log of operations. The configuration is
small (custom rules dominate; a million of them is about 60 MB of JSON), copies are rare, and a
snapshot cannot drift the way a replayed log can after a missed entry. The replica diffs the
snapshot against its own by resource ID and writes only the differences, in one transaction with
one audit entry (actor `replication`, node `dns1`, before and after versions). Resources keep the
primary's IDs, revisions and times, so the replica is an exact copy and `If-Match` revisions mean
the same on both nodes. Snapshots carry the store's schema version, and a replica refuses another
schema: both nodes must run the same goethite version.

**Long polling.** The replica asks `GET /cluster/v1/config?epoch=…&version=…&wait=55`. The
primary answers at once if it has something newer. Otherwise it waits on a watch channel the
store signals after each commit, and answers when a change lands, or with 204 after the wait.
Changes reach the replica within milliseconds, with one request a minute when nothing changes, no
push channel and no state on the primary. Failures back off from 1 s to 30 s. Each distinct error
is logged once, and the replica keeps its configuration meanwhile.

**Mutual TLS with node names.** The channel is HTTP/1.1 inside TLS 1.3 on its own port (8054 by
default), never the API's. `goethite cluster init` creates a private cluster CA (ECDSA P-256, with
rcgen). `goethite cluster cert <node>` issues each node a certificate whose only name is
`<node>.node.goethite.invalid`, valid for both server and client authentication. Each node
accepts only certificates from that CA naming the configured peer, in both directions:

- the replica checks the server is the primary it expects;
- the primary checks the client is its configured replica.

A certificate stolen from another cluster, or issued to a third node of this one, gets nowhere.
The CA's name is derived from its public key, so issuing a certificate needs only `ca.key`,
without parsing `ca.crt` (one less parser); the new certificate is then checked against
`ca.crt`. Keys are written with mode 0600 and never overwritten without `--force`.

**Off the DNS path.** Copies are applied by the control plane like API changes: the filter is
rebuilt off the async runtime only when lists or rules changed, and lists are downloaded only
when lists changed. The listener reuses the API server's accept loop (connection limit 8,
handshake and header timeouts).

## Consequences

- While the primary is down, the configuration cannot change; DNS is unaffected. Promotion is a
  deliberate act until Raft automates it safely.
- A change made on a node while it was a second primary is lost when it is demoted: its
  configuration is replaced by the other's.
- Two nodes both configured as primary would each accept changes. The replica's sync answers
  `not_primary`, so this shows up at once in the logs and the cluster status.
- Each node downloads filter lists itself. Lists given by `path` must exist on both nodes.
- The query log, statistics and pause state stay per node. Cluster-wide statistics aggregate
  them on request.
- Certificates are valid for 10 years and there is no revocation list. To remove a node for good,
  create a new CA and issue new certificates to the remaining nodes.

## Alternatives considered

- **Both nodes writable, last write wins.** It is always writable, but changes made on both sides
  of a partition can overwrite each other silently. Rejected in favor of no surprises.
- **Replaying the audit log.** It is finer grained, but a gap, a pruned entry or a bug makes the
  replica drift forever, and it needs a second encoding of every change. Snapshots are simpler and
  self-healing.
- **Raft now.** Raft would also need membership changes and a third vote to survive a node loss,
  which is overkill for two nodes. It is planned for 1.0, behind the same store interface.
- **Bring-your-own certificates.** No new dependency, but more operator work and more room for
  mistakes (wrong SANs, wrong key usages).
