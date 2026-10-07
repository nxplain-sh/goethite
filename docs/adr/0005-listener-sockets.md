# ADR 0005: Listener sockets bound before the runtime, per-core on Linux, limited per client

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

goethite listens on port 53, which needs privileges, and must give them up as soon as the
sockets exist ([`AGENTS.md`](../../AGENTS.md#security-rules-non-negotiable)). On Linux, dropping
privileges with raw system calls only affects the calling thread, and the tokio runtime starts a
thread per core. One UDP socket per address funnels every query through one receive loop. And a
resolver reachable by spoofed packets can be used to flood a victim with answers (B1 in the
[threat model](../THREAT_MODEL.md)).

## Decision

- `Listeners::bind` binds every socket with the standard library, through socket2, before the
  runtime is built; `Server::new` registers them with tokio later. The binary binds, then (in a
  later change) drops privileges, then starts the runtime, all while it has a single thread.
- `listen` takes several addresses. IPv6 sockets are IPv6-only, so `0.0.0.0:53` and `[::]:53` can
  be listened on side by side, and each family is explicit.
- On Linux each address gets several UDP sockets with `SO_REUSEPORT`, one per core by default (at
  most 64): the kernel spreads datagrams over them by source, and each socket has its own receive
  loop. `SO_REUSEPORT` is only set when there are several sockets. Other platforms, development
  only, get one socket: BSD and macOS semantics do not balance the load.
- The UDP in-flight limit, the TCP connection limit and the per-client TCP limit are shared by
  all sockets of all addresses.
- UDP queries are rate limited per client network with GCRA (one timestamp per network), before
  they are decoded, in the receive loop. Over the limit, every `slip`-th query gets an empty TC=1
  answer, as in BIND's response rate limiting; the rest are dropped. The table of networks is
  sharded and bounded; when full, untracked networks share one bucket instead of evicting or
  being let through. Loopback is exempt.

This is a per-client query limit, not BIND's per-(client, answer) RRL: goethite is a resolver for
its own clients, where one client asking many different names is the abuse, not one name asked
many times.

## Consequences

- Sockets can be inherited or handed over later (graceful upgrades in Phase 3) because binding is
  already separate from serving.
- A socket bound to a wildcard address on a multihomed host may answer from another source
  address than the query was sent to, until `IP_PKTINFO` support lands (backlog).
- Rate limiting adds a sharded mutex lookup per UDP query; the hot path otherwise stays the same.
- Defaults (300 queries/s, bursts of 1000, per IPv4 address and IPv6 /64) favour not breaking
  busy networks behind one router over strict limits; a public resolver should lower them.
