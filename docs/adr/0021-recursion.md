# ADR 0021: Recursive resolution

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

goethite forwards to upstream resolvers, which see every name a network looks up. Phase 4 plans
recursive resolution with DNSSEC validation, with our own iterative resolver and validator
(approved, with hickory-proto's DNSSEC feature for signature checks only). This milestone is
the resolution, with no new dependency; DNSSEC validation follows.

## Decision

**Recursion instead of forwarding, chosen per node.** `[recursion] enabled = true` replaces the
`[[upstream]]` tables: a config has one or the other. The rest of the pipeline does not change:
filtering and CNAME uncloaking, the answer cache, rebinding protection, the query log (the
outcome stays `forwarded`, with the authoritative server that gave the final answer as the
upstream) and metrics. `/api/v1/status` gains a `recursion` section; the dashboards show it in
place of the upstreams.

**Our own iterator** (`goethite_resolver::recurse`), from IANA's root hints, primed at start
(RFC 8109) and only replaced by a priming answer that comes with addresses. For each name: the
closest known zone cut, referrals followed down, CNAMEs followed to the end; name servers
without glue are looked up themselves. QNAME minimisation (RFC 9156) is on by default, in its
relaxed form: a minimised query that fails or gets NXDOMAIN is asked again with the whole name,
since some servers deny empty non-terminals. The labels shown per step follow the RFC's
MAX_MINIMISE_COUNT (10) and MINIMISE_ONE_LAB (4), and an underscore label shows the rest.
DS questions go to the parent.

**Bailiwick in one pure function** (`recurse::classify`, fuzzed by `classify_response`): a
server asked as a server of zone Z is believed only about Z. Answers are the CNAME chain from
the name asked while it stays in Z, and the records at its end; a referral must be to a zone
strictly below Z containing the name (for DS, not the name itself); glue is taken only for that
referral's name servers within Z. Everything else, an upward referral or records about other
zones, is ignored and never cached. A server that is not authoritative is lame and the next one
is asked.

**The forwarder's defenses, shared.** Exchanges moved into one module used by both: a fresh UDP
socket with a random port and a random ID per query, the response matched on ID, opcode and the
question in exactly the case sent, TCP when truncated. 0x20 is on for every server; one that
answers with the case changed is asked again without it, and remembered. Names a server
compressed against the randomized question are given their own case back before anyone sees
them.

**Everything bounded.** Per client query: 64 queries sent and 6 seconds, every nested lookup
included. Per name: 32 referrals; name server address lookups nest at most 4 deep, at most 4
per zone, at most 12 addresses tried. CNAME chains: the existing limit of 16. In flight: 1,024
exchanges. The infrastructure tables (zone cuts, addresses, server statistics) hold 20,000
entries each and keep records between 30 seconds and a day. Locks are only held for map
operations, never across an `.await`.

**Special-use names answered locally**: `localhost` with the loopback addresses; `invalid`,
`test`, `onion`, `local`, `home.arpa`, `internal` and the reverse zones of private, loopback,
link-local, shared and documentation addresses (RFC 6761, 6303, 7686, 7793, 8375) as NXDOMAIN
with an SOA, so they never leak to the root and are cached.

**Tests against a simulated DNS.** Recursion reaches servers through a small `Network` trait, so
unit tests run a whole hierarchy in memory: priming, minimisation, CNAMEs into zones without
glue, poisoning attempts, silent, truncating and case-losing servers, denied empty
non-terminals, CNAME loops and deadlines. One test uses real sockets; and goethite was checked
against the real root servers: 50 popular domains gave the same status as Quad9.

## Consequences

- No upstream sees the network's names; each authoritative server sees its part of them.
- The first query in a new zone costs a few round trips.
- Names only the local router knows (`printer.lan`) need forwarding; forwarding chosen domains
  while recursing for the rest is backlog, as are request coalescing, prefetching and serving
  stale answers.
- DNSSEC validation is the next milestone: it needs the DO bit, DS and DNSKEY lookups along the
  same path.
