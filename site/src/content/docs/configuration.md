---
title: Configuration reference
description: Every setting in goethite's TOML config file, with its default and limits.
---

goethite reads one TOML file, given with `--config`. Every setting has a default, except that at
least one `[[upstream]]` is required. Unknown keys are errors, so a typo never silently falls back
to a default. Run `goethite check-config --config <path>` to check a file. The commented
[example config](https://github.com/nxplain-sh/goethite/blob/main/config/goethite.example.toml)
is a good starting point.

The file is read at startup. `SIGHUP` (`systemctl reload goethite`) re-reads the filter lists but
not the file itself; restart goethite after changing it. Files over 1 MiB are refused.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `"127.0.0.1:15353"` | Addresses for DNS over UDP and TCP: one (`"0.0.0.0:53"`) or a list (`["0.0.0.0:53", "[::]:53"]`), at most 16. IP addresses with a port, not hostnames. IPv6 addresses accept only IPv6, so list both families to serve both. |
| `udp_sockets` | one per CPU core | UDP sockets per address on Linux (`SO_REUSEPORT`), 1 to 64. Other platforms use one. |
| `max_tcp_connections` | `256` | TCP connections served at once, 1 to 100,000. More are closed on accept. |
| `max_tcp_connections_per_client` | `16` | TCP connections at once from one client (an IPv4 address or an IPv6 /64), 1 to `max_tcp_connections`. |
| `user` | unset | On Linux, the user to switch to after binding when started as root (see [privileges](../security/#privileges)). Leave unset under the systemd unit. |

The development default port, 15353, needs no root. Port 5353 is avoided because multicast DNS
uses it.

### `[server.rate_limit]`

UDP queries per client network; see [rate limiting](../security/#rate-limiting).

| Key | Default | Meaning |
| --- | --- | --- |
| `queries_per_second` | `300` | Average queries per second per client network, up to 1,000,000. `0` turns rate limiting off. |
| `burst` | `1000` | Queries a quiet client network may send at once, 1 to 1,000,000. |
| `slip` | `2` | Every `slip`-th limited query gets an empty truncated answer (so real clients retry over TCP), 0 to 10. `0` drops them all. |
| `ipv4_prefix` | `32` | Leading bits of an IPv4 address that make one client network, 8 to 32. |
| `ipv6_prefix` | `64` | Leading bits of an IPv6 address that make one client network, 16 to 128. |
| `max_clients` | `65536` | Client networks tracked at once, 16 to 1,000,000. Beyond that, untracked networks share one limit. |

Loopback clients are never limited.

## `[[upstream]]`

The resolvers goethite forwards to, tried in the order they appear, with failover. At least one
is required, and at most 16 are allowed. An upstream that fails three times in a row is skipped
for 30 seconds.

| Key | Default | Meaning |
| --- | --- | --- |
| `address` | required | IP address, optionally with a port: `"9.9.9.9"`, `"9.9.9.9:853"`, `"[2620:fe::fe]:853"`. Not a hostname. The port defaults to 53 for `udp` and `tcp`, 853 for `tls` and 443 for `https`. |
| `protocol` | `"udp"` | `"udp"` (retried over TCP when the answer is truncated), `"tcp"`, `"tls"` (DNS over TLS) or `"https"` (DNS over HTTPS, HTTP/2). |
| `tls_name` | | For `tls`, required: the name the server's certificate must be valid for. |
| `url` | | For `https`, required: the query URL, such as `"https://dns.quad9.net/dns-query"`. Its host is the name the certificate must be valid for. |
| `randomize_case` | `true` | 0x20 case randomization of query names, a defense against spoofed answers. Turn it off only for an upstream that does not preserve case. |

Certificates are checked against the Mozilla root certificates built into goethite, not the
operating system's store. Each query has 2 seconds per upstream and 4 seconds in total.

## `[cache]`

| Key | Default | Meaning |
| --- | --- | --- |
| `max_entries` | `10000` | Answers kept, at most 1,000,000. `0` turns the cache off. |
| `min_ttl` | `0` | Keep positive answers at least this many seconds, even if their TTL is shorter. |
| `max_ttl` | `86400` | Keep positive answers at most this many seconds (at most one week). |
| `max_negative_ttl` | `3600` | Keep NXDOMAIN and NODATA answers at most this many seconds (at most one day). |

## `[filter]`

See [Filtering](../filtering/) for the rule syntax.

Filtering configuration lives in goethite's [store](#store), where the API changes it. This table
**seeds the store on the first start** and is then only read by `goethite import`: the store is the
source of truth, so if the table changes later, goethite logs a warning and keeps what the store
says. To apply the table again, stop goethite and run `goethite import --config <file>`, which
replaces the lists and rules that came from the config file and keeps those created through the
API.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Whether filtering is on (the `protection` setting in the store). |
| `block_response` | `"null_ip"` | How blocked names are answered: `"null_ip"` (`0.0.0.0` / `::`), `"nxdomain"` or `"refused"`. |
| `blocked_ttl` | `10` | TTL of the null-IP answers, in seconds (at most one day). |
| `rules` | `[]` | Rules written into the config, at most 10,000. Each must be a supported rule; anything else is an error. |
| `cache_dir` | `lists` in the state directory | Where downloaded lists are kept. Relative paths are relative to the config file. This one is read on every start. |
| `update_hours` | `24` | How often downloaded lists are refreshed, 1 to 168 hours, with up to 10% random delay. |

### `[[filter.list]]`

Up to 63 lists, each with exactly one of:

| Key | Meaning |
| --- | --- |
| `path` | A list file on disk. Relative paths are relative to the config file. |
| `url` | An `https://` URL. The list is downloaded at startup and every `update_hours`, checked, and kept in `cache_dir`, so goethite starts with the last good copy when offline. |

Lists may be at most 128 MiB.

## `[store]`

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `goethite.redb` in the state directory | goethite's database: lists, rules, groups, clients, schedules, settings and the audit log. Relative paths are relative to the config file. |

The state directory is systemd's `StateDirectory` (`/var/lib/goethite` with the
[shipped unit](../install/)) or, without it, the config file's directory. The file is created
readable by goethite's user only, and only one goethite process can open it at a time.

## `[security]`

| Key | Default | Meaning |
| --- | --- | --- |
| `rebinding_protection` | `true` | Remove private, loopback and link-local addresses from forwarded answers for public names (see [DNS rebinding protection](../security/#dns-rebinding-protection)). |
| `private_domains` | `["lan", "home.arpa", "internal", "local"]` | Names below these may resolve to private addresses. Setting it replaces the defaults. |

## Logging

Logs go to standard error, and the `RUST_LOG` environment variable sets the level (default
`info`). For example, `RUST_LOG=debug` shows dropped and rejected packets, and
`RUST_LOG=goethite_resolver=debug` shows only the resolver's details.
