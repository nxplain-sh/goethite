---
title: Filtering
description: Blocking names with hosts files, domain lists and AdGuard-style rules.
---

goethite blocks names using rules from list files and from the config. One parser reads hosts
files, plain domain lists and the core of the AdGuard DNS filter syntax, deciding the format line
by line, so lists can be mixed freely.

## Rule syntax

| Rule | Effect |
| --- | --- |
| `0.0.0.0 ads.example` | blocks exactly `ads.example` (hosts format; `127.0.0.1`, `::` and `::1` work too) |
| `ads.example` | blocks exactly `ads.example` (domain list) |
| `*.ads.example` | blocks every name below `ads.example`, but not `ads.example` itself |
| `\|\|ads.example^` | blocks `ads.example` and every name below it |
| `\|ads.example^` | blocks exactly `ads.example` |
| `.ads.example^` | blocks every name below `ads.example`, but not `ads.example` itself |
| `://ads.example^` | blocks exactly `ads.example` (URL-style anchor) |
| `@@\|\|good.example^` | an exception: `good.example` and the names below it are never blocked |

Exceptions win over blocks, whatever the order of the rules. Matching ignores case. Lines starting
with `!` or `#`, `[Adblock Plus 2.0]`-style headers and blank lines are ignored, and hosts files
may end lines with a `# comment`. Hosts entries for `localhost` and similar system names are
skipped.

Not supported yet, so counted and skipped rather than guessed at: regular expressions
(`/ads[0-9]+/`), modifiers (`||ads.example^$important`), patterns without a `||` or `|` anchor,
wildcards inside a name, names with non-ASCII characters, and hosts entries with a real address
(those are rewrites, not blocks). The log shows how many lines of each list were used, unsupported
and invalid.

## Configuration

Lists, rules and the filtering settings live in goethite's store, which the
[REST API](../api/) edits. [Groups](../groups/) decide which lists apply to which clients. The `[filter]` table in the config file **seeds the store on the first
start**; after that the store is the source of truth. If you edit `[filter]` later, goethite logs
a warning and keeps the store as it is. To apply your edits, stop goethite and import them:

```sh
goethite import --config /etc/goethite/goethite.toml
```

Importing replaces the lists and rules that came from the config file, adds new lists to the
default group, and updates the settings. Lists and rules created through the API stay.

```toml
[filter]
enabled = true
block_response = "null_ip"   # "null_ip", "nxdomain" or "refused"
blocked_ttl = 10             # seconds, for the null-IP answers
rules = [
  "||doubleclick.net^",
  "@@||allowed.example^",
]

cache_dir = "lists"          # where downloaded lists are kept
update_hours = 24            # how often URL lists are refreshed (1 to 168)

[[filter.list]]
path = "/var/lib/goethite/lists/hosts.txt"

[[filter.list]]
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

Each `[[filter.list]]` has either a `path` or a `url`. Relative paths are relative to the config
file. Unlike lines in a list, each entry in `rules` must be a supported rule: anything else is
reported as an error when the config is loaded.

`block_response = "null_ip"` answers `A` queries with `0.0.0.0`, `AAAA` with `::`, and other types
with an empty answer, so applications fail fast instead of trying another resolver. `nxdomain` says
the name does not exist; `refused` refuses the query.

Blocking applies before the cache, so a name that becomes blocked is blocked at once even if its
answer is cached. Local names such as `goethite.test` are answered before filtering.

## Recommended and default lists

goethite recommends ten lists for ads and trackers, each checked to download and read cleanly:
HaGeZi Multi Light, Normal, Pro and Pro++, the AdGuard DNS filter, OISD Small and Big, Steven
Black's Unified Hosts, AdAway and Peter Lowe's list. The [web UI](../web-ui/) shows them on the
Lists page with what each blocks, its license and its size, and adds one in a click, used by the
default group at once (`GET /api/v1/lists/recommended` lists them for scripts). HaGeZi, OISD and
AdGuard overlap a lot: one of them is usually enough.

A **new node** starts with HaGeZi Multi Normal in its default group: all-round protection from
ads, trackers, telemetry, phishing and malware, made for DNS blocking, rarely breaking anything.
It is an ordinary list, to keep, replace or remove. A config file that lists its own
`[[filter.list]]` entries, or sets `default_lists = false` in `[filter]`, starts without it;
nodes that already have a store are never changed.

## Finding more lists

The Lists page's **Find lists** searches the [FilterLists](https://filterlists.com) directory:
the 1,100 or so lists goethite can read (hosts files, domain lists, adblock-style domain rules),
by name, description and topic. Allowlists are left out, since goethite would block their
domains. Adding a list opens the usual form, filled in, so you check it before it filters anyone.

goethite's node fetches the directory from `api.filterlists.com` when someone opens the page, not
the browser, and keeps it for a day. Names, descriptions and licenses come from FilterLists and
its contributors and may be out of date: check a list's home page. `directory = false` in
`[filter]` turns the directory off.

## Blocking whole services

To block a service such as TikTok or YouTube for some devices, without hunting for its domains,
use a group's [blocked services](../groups/#blocked-services) instead of a list.

## Downloaded lists

Lists with a `url` are downloaded at startup and then every `update_hours`, with up to 10% random
delay so many installations do not hit list servers at the same moment:

- Only `https://` URLs are accepted, and redirects must stay on HTTPS. Certificates are checked
  against the Mozilla roots built into goethite.
- The list host is resolved through goethite's own upstreams, skipping the filter, so a list that
  blocks its own host still updates.
- Unchanged lists are revalidated with `ETag` and `Last-Modified` and not downloaded again.
- Downloads are limited to 128 MiB and two minutes.
- A download replaces the last good copy only if it holds rules and more rules than invalid or
  unsupported lines. An HTML error page, an empty file or a list that turned into something else
  is rejected, and the last good copy stays.
- Copies are kept in `cache_dir` and written atomically, so goethite starts with them even when
  it cannot reach the network.

## CNAME uncloaking

Some trackers hide behind a CNAME: `metrics.shop.example` is an alias for
`collect.tracker.example`, so blocking `tracker.example` alone would miss it. goethite checks every
CNAME target in an answer against the same rules and blocks the answer if one of them is blocked,
whether the answer came from an upstream or from the cache. The query log names the CNAME that
matched. An exception for the name asked for (`@@||shop.example^`) wins over its CNAMEs.

## Reloading

Send `SIGHUP` to re-read the list files and the last downloaded copies without restarting:

```sh
kill -HUP "$(pidof goethite)"
```

The new rules are compiled in the background while queries keep using the old ones, then swapped
in atomically. If compiling fails, the current filter stays. A list file that cannot be read is
logged and skipped, so a missing list never stops resolution. The config file itself is not
re-read: restart for changes to node settings, and use `goethite import` for `[filter]`.

## Limits

- List files up to 128 MiB, lines up to 4096 bytes.
- At most 5,000,000 rules in total, 63 list files and 10,000 rules in the config.
- A million rules take about 6 MiB of memory, and a lookup takes well under a microsecond.
