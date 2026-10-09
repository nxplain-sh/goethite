---
title: Local records
description: Answer names on your own network, such as nas.lan, from goethite itself, for every client and before any filter.
---

goethite can answer names itself: a device on your network, such as `nas.lan`, or every name
below one, such as `*.home.example` for the services behind a reverse proxy. These local records
answer every client, before the filter and whether filtering is on or paused, and they are part of
the replicated configuration, so both nodes of a [cluster](../ha/) answer them alike.

Add them in the web UI's **Records** page, or through the [API](../api/):

```sh
api -X POST http://127.0.0.1:8053/api/v1/records \
  -d '{"name": "nas.lan", "type": "A", "value": "192.168.1.10"}'
api -X POST http://127.0.0.1:8053/api/v1/records \
  -d '{"name": "*.home.example", "type": "CNAME", "value": "proxy.lan", "ttl": 60}'
```

| Field | Meaning |
| --- | --- |
| `name` | The name, such as `nas.lan`, or `*.` and a name for every name below it, not that name itself. Names under `goethite.test` are goethite's own and cannot be used. |
| `type` | `A` (an IPv4 address), `AAAA` (an IPv6 address) or `CNAME` (another name). |
| `value` | The address, or for a `CNAME` the name it points to. |
| `ttl` | How long clients may keep the answer, in seconds, 0 to 86,400. Defaults to 300. |
| `enabled` | Whether it is answered. Defaults to `true`. |
| `comment` | Free text. |

## How they are answered

- **An exact name wins** over a wildcard, and a closer wildcard over one further up:
  `pi.lab.home.example` takes `*.lab.home.example` before `*.home.example`.
- **A name with records answers only from them.** `nas.lan` with an `A` record answers `AAAA`
  questions with an empty answer (NODATA) instead of asking an upstream.
- **A `CNAME` is followed.** goethite answers the `CNAME` and then the target's records: from
  other local records if it has them, otherwise resolved like any other name, through the filter,
  the cache and the upstreams. A `CNAME` to a blocked name is blocked. Local `CNAME`s that loop
  get `SERVFAIL`.
- **A name with a `CNAME` has no other record**, as in DNS; goethite refuses the second one.

Up to 10,000 records. Answers come with the authoritative flag set and are written to the query
log as `local`.

## Coming from Pi-hole or AdGuard Home

Pi-hole's *Local DNS records* and *CNAME records* and AdGuard Home's *DNS rewrites* are local
records in goethite. `goethite migrate` brings them over with the rest of the configuration.
