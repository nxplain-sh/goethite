---
title: Recursion
description: Resolve names from the root servers yourself, instead of asking an upstream resolver.
---

By default goethite forwards the queries it does not answer itself to the
[upstream resolvers](../configuration/#upstream) you configure. With **recursion**, it asks no
resolver at all: it starts at the root servers and follows the DNS down to the servers that
hold each name, as Unbound or BIND do. No single company sees every name your network looks
up.

```toml
[recursion]
enabled = true
```

A config file has either `[[upstream]]` resolvers or recursion, not both. Filtering, groups,
the cache, rebinding protection and the query log work as before; the query log shows the
server that gave the final answer as the upstream.

## How it works

goethite starts from the root servers built into it, and asks one of them who they are when it
starts (priming, RFC 8109). For each name it asks the servers of the closest zone it knows,
follows referrals down, and follows CNAMEs to the end. What it learns along the way is kept:
which servers hold which zones, their addresses and how fast each answers, so the next query
for a name nearby goes straight to the right server.

- **QNAME minimisation** (RFC 9156) is on: each server sees only as much of a name as it needs.
  The root servers see `com`, not `www.example.com`. Turn it off with
  `qname_minimisation = false`.
- **Bailiwick.** A server is believed only about its own zone: answers for names in it,
  referrals to zones below it, and addresses for name servers in it. Anything else it sends is
  ignored, never cached.
- **Spoofing defenses**, as for upstreams: a new random source port and ID for every query,
  the name in random case (0x20) that the answer must repeat exactly, and TCP when an answer
  is truncated. A server that does not repeat the case is asked without it.
- **Servers** that answer slowly or not at all are tried last; one that fails three times in a
  row is set aside for a minute.
- **IPv6.** goethite asks servers over IPv6 too when this host has an IPv6 route; set
  `ipv6 = true` or `false` to decide yourself.

## Names that stay home

Some names are never asked about on the internet, since the answer is known and the question
would only tell others what your network is doing:

- `localhost` and names below it answer `127.0.0.1` and `::1` (RFC 6761);
- `invalid`, `test`, `onion`, `local`, `home.arpa` and `internal` do not exist;
- reverse lookups of private, loopback, link-local, shared (100.64.0.0/10) and documentation
  addresses do not exist (RFC 6303, RFC 7793).

With recursion, names your router hands out, such as `printer.lan` or `nas.fritz.box`, cannot
be found, since only the router knows them. If you need them, keep forwarding for now:
sending chosen domains to the router while resolving the rest is planned.

## Limits

One client query may send at most 64 queries to authoritative servers, every lookup included,
and take at most 6 seconds; after that it is answered with SERVFAIL. At most 32 referrals are
followed for one name, and name server addresses are looked up at most four levels deep. 1,024
queries to authoritative servers may be in flight at once. The tables of zones, addresses and
servers hold at most 20,000 entries each.

The first query for a name in a zone goethite has not seen yet takes a few round trips, so
expect tens to hundreds of milliseconds where a large public resolver would answer from its
cache; after that, answers come from goethite's cache.

The [metrics](../api/#metrics) count the queries sent (`goethite_recursion_queries_total`),
timeouts, unresolved queries and the zones known; `/api/v1/status`, the web UI's dashboard and
the TUI show the same.

DNSSEC validation is not done yet: it comes in a later version.
