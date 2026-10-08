# ADR 0024: A DNS leak test

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

goethite filters only what reaches it. Devices bypass it without anything looking wrong:
- browsers with secure DNS turned on;
- VPNs;
- hardcoded DNS servers;
- a router that hands out a second DNS server.

The user asked for a DNS leak test, chose a local check over an egress test, and asked for it in
the web UI, the API and the TUI. An egress test ("which resolvers reach the internet",
dnsleaktest.com's kind) would need a third-party service.

## Decision

**Names only goethite answers.** A test is eight names, `<id>-<n>.leak.goethite.test.`, with
128 random bits in the ID.
- `.test` exists on no public DNS server (RFC 6761), so a lookup that goes elsewhere fails there.
- goethite now answers every name under `goethite.test` itself: `NXDOMAIN` unless it is a
  built-in record, authoritative, never forwarded, never filtered. So test names never leave the
  node, even when forwarding.

**Lookups are recorded where every query is observed.** The binary's query observer, which
already feeds the query log and the metrics, passes each name to the test registry. Any other
name costs one suffix comparison and no lock. A test name is recorded with how it arrived:
- address, protocol and type;
- the client and group goethite identified it as;
- whether filtering applies (`Resolution` now carries the client's filtering flag).

Names of tests this node did not make are ignored.

**The registry is bounded and in memory, per node:**
- 32 tests, each kept an hour;
- 64 lookups per test.

Tests are not configuration: no store, no audit log, and replicas do not forward them. Each test
also records the address its creator connected to the API from. When lookups arrive from
another address, the device is behind a forwarder (often the router), and goethite cannot tell
its devices apart.

**The browser looks names up by loading images** from `http(s)://<name>/…`. The images never
load. The web UI's Content Security Policy gains
`img-src http://*.leak.goethite.test https://*.leak.goethite.test`, and nothing else. The page
then reads the result (polling briefly for late lookups) and says, in words and a badge:
- NO LEAK, PARTIAL LEAK or LEAK;
- over which protocols and from which addresses;
- as which client and group, and whether filtering is on.

**API:** `POST /api/v1/leak-tests`, `GET /api/v1/leak-tests` and `GET /api/v1/leak-tests/{id}`,
behind the admin token like the rest of the API.

**The TUI** gets a sixth screen listing the tests. Its `t` key tests the TUI's own machine by
resolving the names through the system resolver (`getaddrinfo`).

The name parser is fuzzed (`parse_leak_probe`).

## Consequences

- The test sees lookups made the way the browser makes them. Apps with their own resolver are
  not covered, and a browser that falls back to the system resolver only for names its own
  resolver cannot find passes. The docs say so.
- A device behind another resolver sends the random test names to that resolver, which learns
  only that a test ran.
- In a pair, a test only sees lookups that reach the node that made it. Cluster-wide tests are
  in the backlog.
- Running the test needs the admin token. An open test page for family devices is in the
  backlog.
