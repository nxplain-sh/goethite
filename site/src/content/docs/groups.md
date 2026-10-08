---
title: Clients, groups and schedules
description: Different filtering for different devices, at different times.
---

By default everyone is in the **default group**, which uses every list imported from the config
file plus the custom rules. To filter some devices differently, put them in a group of their own.
All of this is configured through the [REST API](../api/); the [terminal UI](../tui/) shows it
and turns lists on and off.

## Groups

A group says which lists apply to its clients, whether they are filtered at all, and whether safe
search is on:

```sh
api -X POST http://127.0.0.1:8053/api/v1/groups -d '{
  "name": "Kids",
  "safe_search": true,
  "lists": [
    {"list": "li_cfg_1c0e…"},
    {"list": "li_8d2f…", "schedule": "sc_41aa…"}
  ]
}'
```

Custom rules (`/api/v1/rules`) apply to every group with filtering on. A list in a group applies
always, or only while a schedule is active. A group with `"filtering": false` is not filtered at
all: no lists, no custom rules, no safe search. The default group can be changed but not deleted.
New lists are not added to any group by themselves, except lists imported from the config file,
which join the default group.

## Clients

A client is a device or a network, identified by its addresses or its client IDs:

```sh
api -X POST http://127.0.0.1:8053/api/v1/clients -d '{
  "name": "Tablet",
  "addresses": ["192.168.1.23", "fd00::23"],
  "ids": ["tablet"],
  "group": "gr_cce7…"
}'
```

Addresses are single addresses or networks in CIDR notation (`192.168.1.0/24`), with no host bits
set. If several clients' networks contain an address, the longest one wins, so a device can be its
own client inside a network that is another client. Clients goethite does not know are in the
default group. The query log and the statistics show clients by ID.

Client IDs name a device over [DNS over TLS, HTTPS and QUIC](../encrypted-dns/#client-ids),
wherever it is: a query that carries a known ID belongs to that client before its address is looked at. IDs
are 1 to 63 lowercase letters, digits and hyphens, at most 16 per client, and unique. A client
needs an address or an ID, or both.

## Schedules

A schedule is a set of weekly time windows in a time zone:

```sh
api -X POST http://127.0.0.1:8053/api/v1/schedules -d '{
  "name": "School hours",
  "time_zone": "Europe/Berlin",
  "windows": [
    {"days": ["mon", "tue", "wed", "thu", "fri"], "start": "08:00", "end": "13:30"}
  ]
}'
```

An `end` before the `start` runs past midnight into the next day (`22:00` to `07:00`), and `24:00`
ends a window at midnight. goethite checks the schedules at the start of every minute, in their
time zone, so daylight saving time is handled.

## Safe search

With safe search on, a group's clients are sent to the filtered version of the big search engines,
whatever their browser settings say. goethite answers their search hosts with a CNAME to the
engine's safe host:

| Engine | Hosts | Sent to |
| --- | --- | --- |
| Google | `google.<tld>` and `www.google.<tld>` for all 187 of Google's domains | `forcesafesearch.google.com` |
| YouTube | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrict.youtube.com` (strict) |
| Bing | `www.bing.com`, `bing.com` | `strict.bing.com` |
| DuckDuckGo | `duckduckgo.com`, `www.duckduckgo.com`, `start.duckduckgo.com` | `safe.duckduckgo.com` |

The query log shows these queries as `safe_search`.
