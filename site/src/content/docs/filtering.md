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
file.

`block_response = "null_ip"` answers `A` queries with `0.0.0.0`, `AAAA` with `::`, and other types
with an empty answer, so applications fail fast instead of trying another resolver. `nxdomain` says
the name does not exist; `refused` refuses the query.

Blocking applies before the cache, so a name that becomes blocked is blocked at once even if its
answer is cached. Local names such as `goethite.test` are answered before filtering.

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

## Reloading

Send `SIGHUP` to re-read the list files and the last downloaded copies without restarting:

```sh
kill -HUP "$(pidof goethite)"
```

The new rules are compiled in the background while queries keep using the old ones, then swapped
in atomically. If compiling fails, the current filter stays. A list file that cannot be read is
logged and skipped, so a missing list never stops resolution. The config file itself is not
re-read; restart for config changes.

## Limits

- List files up to 128 MiB, lines up to 4096 bytes.
- At most 5,000,000 rules in total, 64 list files and 10,000 rules in the config.
- A million rules take about 6 MiB of memory, and a lookup takes well under a microsecond.
