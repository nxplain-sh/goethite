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
always, or only while a schedule is active, and so does a [blocked service](#blocked-services). A group with `"filtering": false` is not filtered at
all: no lists, no custom rules, no safe search. The default group can be changed but not deleted.
New lists are not added to any group by themselves, except lists imported from the config file,
which join the default group.

## Blocked services

A group can block a whole service, such as TikTok, YouTube, Discord or Roblox, without anyone
knowing which of its names to block: always, or while a schedule is active. In the [web UI](../web-ui/)
the group editor lists the services by kind, with a toggle each; through the API:

```sh
api -X PUT http://127.0.0.1:8053/api/v1/groups/gr_cce7… -d '{
  "name": "Kids",
  "blocked_services": [
    {"service": "tiktok"},
    {"service": "youtube", "schedule": "sc_41aa…"}
  ]
}'
```

A blocked service blocks every name its rules cover, whatever the group's lists and custom rules
say, as long as the group is filtered: pausing, turning protection off or `"filtering": false`
lets it through. The query log shows such blocks as `service:<id>`, with the rule that matched.

The services and their rules come from AdGuard's
[HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) (GPL-3.0), which goethite
downloads with the lists rather than bundles: `GET /api/v1/services` lists them, about 140, with
the rules goethite uses. A few rules goethite cannot read yet (wildcards inside names,
`$dnstype`, `$dnsrewrite`) are left out, so it may block a little less than AdGuard Home. An ID
the catalog does not have blocks nothing. `services = false` in [`[filter]`](../configuration/#filter)
turns blocked services off; `services_file` reads the catalog from a file instead, for nodes
without internet access.

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
engine's safe host, except Yandex, whose safe endpoint is a fixed address answered directly:

| Engine | Hosts | Sent to |
| --- | --- | --- |
| Google | `google.<tld>` and `www.google.<tld>` for all 187 of Google's domains | `forcesafesearch.google.com` |
| YouTube | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrict.youtube.com` (strict) |
| Bing | `www.bing.com`, `bing.com` | `strict.bing.com` |
| DuckDuckGo | `duckduckgo.com`, `www.duckduckgo.com`, `start.duckduckgo.com` | `safe.duckduckgo.com` |
| Ecosia | `www.ecosia.org` | `strict-safe-search.ecosia.org` |
| Pixabay | `pixabay.com` | `safesearch.pixabay.com` |
| Yandex | `ya.ru`, `yandex.<tld>` and their `www.` forms | `213.180.193.56` (an `A` answer) |

The query log shows these queries as `safe_search`.
