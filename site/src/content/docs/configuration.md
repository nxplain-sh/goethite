---
title: Configuration reference
description: Every setting in goethite's TOML config file, with its default and limits.
---

goethite reads one TOML file, given with `--config`. Every setting has a default, except that at
least one `[[upstream]]` is required. Unknown keys are errors, so a typo never silently falls back
to a default. Run `goethite check-config --config <path>` to check a file. The commented
[example config](https://github.com/nxplain-sh/goethite/blob/main/config/goethite.example.toml)
is a good starting point.

The file is read at startup. `SIGHUP` (`systemctl reload goethite`) re-reads the filter lists and
the TLS certificates but not the file itself; restart goethite after changing it. Files over 1 MiB
are refused.

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

Queries per client network, over UDP, TCP, DNS over TLS, HTTPS and QUIC together; see
[rate limiting](../security/#rate-limiting). Which clients may use goethite at all is not set
here but in the replicated settings ([access control](../security/#access-control)).

| Key | Default | Meaning |
| --- | --- | --- |
| `queries_per_second` | `300` | Average queries per second per client network, up to 1,000,000. `0` turns rate limiting off. |
| `burst` | `1000` | Queries a quiet client network may send at once, 1 to 1,000,000. |
| `slip` | `2` | Every `slip`-th limited query gets an empty truncated answer (so real clients retry over TCP), 0 to 10. `0` drops them all. |
| `ipv4_prefix` | `32` | Leading bits of an IPv4 address that make one client network, 8 to 32. |
| `ipv6_prefix` | `64` | Leading bits of an IPv6 address that make one client network, 16 to 128. |
| `max_clients` | `65536` | Client networks tracked at once, 16 to 1,000,000. Beyond that, untracked networks share one limit. |
| `exempt` | `[]` | Addresses or networks never limited, such as `["192.168.0.0/16", "fd00::/8"]`, at most 256. |

Loopback clients are never limited.

### `[server.tls]`

DNS over TLS, HTTPS and QUIC for clients; see [Encrypted DNS](../encrypted-dns/). Without this
table, none is served.

| Key | Default | Meaning |
| --- | --- | --- |
| `cert`, `key` | required | PEM files: the certificate chain and its private key. Read before goethite drops its privileges, and again on `SIGHUP`. Relative paths are relative to the config file. |
| `dot` | none | Addresses for DNS over TLS, usually port 853: one or a list, at most 16. |
| `doh` | none | Addresses for DNS over HTTPS, usually port 443: one or a list, at most 16. Queries go to `/dns-query`. |
| `doq` | none | Addresses for DNS over QUIC, usually UDP port 853: one or a list, at most 16. |
| `server_name` | unset | The name devices use, such as `"dns.example"`. With it, a TLS server name one label below it (`anna-phone.dns.example`) carries a client ID over DoT and DoQ; the certificate should then cover `*.dns.example` too. |
| `require_client_id` | `false` | Answer only DoT, DoH, DoQ and ODoH queries that carry a known client ID; others get `REFUSED`. Turn it on when the listeners are reachable from the internet. |
| `odoh` | `false` | Make the `doh` addresses an [Oblivious DoH](../encrypted-dns/#oblivious-doh) target too: encrypted queries at `/dns-query`, the public key at `/.well-known/odohconfigs`. Needs `doh`. |

At least one of `dot`, `doh` and `doq` is required. No TCP address may be used twice across
`[server]`, `[server.tls]`, `[api]` and `[cluster]`, nor a UDP address across `[server] listen`
and `doq`. Encrypted connections, QUIC ones included, count against `max_tcp_connections` and
`max_tcp_connections_per_client`.

## `[[upstream]]`

The resolvers goethite forwards to, tried in the order they appear, with failover. At least one
is required, unless [`[recursion]`](#recursion) is enabled instead, and at most 16 are allowed. An upstream that fails three times in a row is skipped
for 30 seconds.

| Key | Default | Meaning |
| --- | --- | --- |
| `address` | required | IP address, optionally with a port: `"9.9.9.9"`, `"9.9.9.9:853"`, `"[2620:fe::fe]:853"`. Not a hostname. The port defaults to 53 for `udp` and `tcp`, 853 for `tls` and 443 for `https`. |
| `protocol` | `"udp"` | `"udp"` (retried over TCP when the answer is truncated), `"tcp"`, `"tls"` (DNS over TLS) or `"https"` (DNS over HTTPS, HTTP/2). |
| `tls_name` | | For `tls`, required: the name the server's certificate must be valid for. |
| `url` | | For `https`, required: the query URL, such as `"https://dns.quad9.net/dns-query"`. Its host is the name the certificate must be valid for. |
| `randomize_case` | `true` | 0x20 case randomization of query names, a defense against spoofed answers. Turn it off only for an upstream that does not preserve case. |

Certificates are checked against the Mozilla root certificates built into goethite, not the
operating system's store. Each query has 2 seconds per upstream and 4 seconds in total. Queries to
`tls` and `https` upstreams are [padded](../encrypted-dns/#padding) so their size says less
about the name.

## `[recursion]`

Resolve every name from the root servers down instead of asking `[[upstream]]` resolvers; see
[Recursion](../recursion/). A config file has one or the other.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Resolve recursively. With it, there must be no `[[upstream]]` tables. |
| `qname_minimisation` | `true` | Show each server only as much of a name as it needs (RFC 9156). |
| `ipv6` | unset | Ask servers over IPv6 too. Unset: when this host has an IPv6 route. |
| `dnssec` | `true` | Validate answers with DNSSEC: AD for secure ones, SERVFAIL for bogus ones. See [DNSSEC](../recursion/#dnssec). |

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
| `default_lists` | `true` | Whether a new node with no `[[filter.list]]` starts with goethite's [Balanced preset](../filtering/#recommended-lists-and-presets) (HaGeZi Multi Normal, TIF Mini and Fake) in the default group. Only the first start of a new store looks at it. |
| `directory` | `true` | Whether the node looks lists up for the web UI, only when someone browses them: the [FilterLists directory](../filtering/#finding-more-lists), and the sizes the [recommended lists](../filtering/#recommended-lists-and-presets) state. A node setting, never copied into the store. |
| `services` | `true` | Whether groups can [block services](../groups/#blocked-services): the node downloads AdGuard's services catalog with the lists. A node setting, never copied into the store. |
| `services_file` | none | Reads the services catalog from this file instead of downloading it, for nodes without internet access (re-read on reload). Relative paths are relative to the config file. |
| `local_lists_dir` | `lists` beside the config file | The only directory lists given by a `path` are read from, whether from the config file or the API. A node setting. |
| `on_failure` | `"open"` | What to do when filtering fails: `"open"` keeps resolving (unfiltered if need be) and reports it, `"closed"` refuses to start or answers SERVFAIL. A node setting, never copied into the store. See [Security](../security/#when-filtering-fails). |

### `[[filter.list]]`

Up to 63 lists, each with exactly one of:

| Key | Meaning |
| --- | --- |
| `path` | A list file in `local_lists_dir`. Relative paths are relative to the config file. |
| `url` | An `https://` URL. The list is downloaded at startup and every `update_hours`, checked, and kept in `cache_dir`, so goethite starts with the last good copy when offline. |

Lists may be at most 128 MiB.

## `[store]`

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `goethite.redb` in the state directory | goethite's database: lists, rules, groups, clients, schedules, settings and the audit log. Relative paths are relative to the config file. |

The state directory is systemd's `StateDirectory` (`/var/lib/goethite` with the
[shipped unit](../install/)) or, without it, the config file's directory. The file is created
readable by goethite's user only, and only one goethite process can open it at a time.

## `[api]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Whether the REST API, `/metrics` and the web UI are served. |
| `listen` | `"127.0.0.1:8053"` | Addresses for the API: one or a list. Any address beyond loopback needs `token_sha256`. |
| `token_sha256` | unset | The SHA-256 hash of the admin token, as printed by `goethite token`. Without it, only loopback clients are answered, without authentication. |
| `tls_cert`, `tls_key` | unset | PEM files to serve HTTPS. Read before goethite drops its privileges, so they may be readable by root only. |
| `web_ui` | `true` | Whether the [web UI](../web-ui/) is served at `/` on the same addresses. |
| `docs` | `false` | Whether the [API reference](../web-ui/#api-reference) is served at `/api/docs`, to loopback clients only. |

See [REST API](../api/) for how to use it.

## `[cluster]`

Absent for a node on its own. With it, the node is a member of a cluster whose members agree on
the filtering configuration with Raft. `goethite witness` reads the same table. See
[High availability](../ha/).

| Key | Default | Meaning |
| --- | --- | --- |
| `node` | required | This member's name, as in its certificate: 1 to 63 lowercase letters, digits and hyphens, starting with a letter. |
| `bootstrap` | `false` | Start a new cluster on this node, with its configuration, while it is in none. On one node only; never on a witness. |
| `listen` | `"0.0.0.0:8054"` | Where the member listens for the others, over mutual TLS. Also the address it gives the others when it starts the cluster, so prefer its own address to `0.0.0.0`. |
| `ca` | required | The cluster CA certificate, from `goethite cluster init`. |
| `cert`, `key` | required | This member's certificate and key, from `goethite cluster cert <node>`. Read before goethite drops its privileges. |
| `role` | unset | goethite 0.4's role: `"primary"` starts the cluster, as `bootstrap` does; `"replica"` waits to be added. |

### `[[cluster.member]]`

One table for each other member, up to 15. Only members in a member's config file, or already in
the cluster, may connect to it. The leader adds the members in its config file as they answer.

| Key | Default | Meaning |
| --- | --- | --- |
| `node` | required | The member's name. Only a certificate with that name is accepted for it. |
| `address` | required | The member's `listen` address. |

goethite 0.4's `[cluster.peer]` table, with the same keys, still counts as one member.

## `[vrrp]`

Absent unless the node shares a floating IP with another: the address that whichever node is
healthy holds, moved by `goethite vrrp`. See [High availability](../ha/#a-floating-ip).

| Key | Default | Meaning |
| --- | --- | --- |
| `interface` | required | The network interface the floating IP lives on, such as `"eth0"`. |
| `address` | required | The floating IP (IPv4). It must be in `[server] listen`, or `[server] listen` must include `0.0.0.0`. |
| `peer` | required | The other node's own address on the interface. Announcements from anyone else are ignored. |
| `router_id` | required | 1 to 255: the same on both nodes, and used by no other VRRP pair on the network. |
| `priority` | required | 1 to 254. Of two healthy nodes, the one with the higher priority holds the address. |
| `interval_ms` | `1000` | How often the holder announces itself, a multiple of 10 from 100 to 40950. The other node takes over after about 3.6 intervals of silence. |
| `preempt` | `true` | Whether a node takes the address back when it is healthy again and has the higher priority. |
| `unicast` | `false` | Send announcements straight to `peer` instead of to the multicast group 224.0.0.18, for networks that drop multicast. Set it on both nodes. |
| `check` | from `[server] listen` | Where `goethite vrrp` checks that goethite answers. By default the first listen address other than the floating IP, with `127.0.0.1` or `::1` for `0.0.0.0` or `::`. |

## `[querylog]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Whether answered queries are logged. Statistics are kept either way. |
| `retention_days` | `7` | How long entries are kept, 1 to 365 days. |
| `max_entries` | `1000000` | The most entries kept, 1,000 to 50,000,000; the oldest go first. |
| `anonymize_clients` | `false` | Keep only the /24 of IPv4 and the /56 of IPv6 client addresses, in the log and in the statistics. |

Each entry records when, the client's address (and its known client and group), the protocol, the
name and type asked for, the response code, how the answer came about (cached, forwarded and from
which upstream, blocked and by which rule and list, and so on) and how long it took. A busy home
network logs tens of thousands of queries a day, which takes a few megabytes. Hourly statistics,
with the 100 names, blocked names and clients seen most each hour, are kept for 30 days.

Logging never slows answers down: queries are queued, and if the writer falls behind, entries are
dropped and counted (`goethite_querylog_dropped_total` in the metrics) rather than delaying
anyone.

## `[security]`

| Key | Default | Meaning |
| --- | --- | --- |
| `rebinding_protection` | `true` | Remove private, loopback and link-local addresses from forwarded answers for public names (see [DNS rebinding protection](../security/#dns-rebinding-protection)). |
| `private_domains` | `["lan", "home.arpa", "internal", "local"]` | Names below these may resolve to private addresses. Setting it replaces the defaults. |
| `sandbox` | `true` | Whether goethite confines itself with Landlock and seccomp on Linux ([the sandbox](../security/#the-sandbox)). Also read by `goethite witness` and `goethite vrrp`. |

## `[telemetry]`

Sends goethite's metrics to an OpenTelemetry collector over OTLP/HTTP, as well as serving them at
`/metrics`. Nothing is sent without `endpoint`. See [Metrics and telemetry](../observability/).

| Key | Default | Meaning |
| --- | --- | --- |
| `endpoint` | unset | The collector's OTLP/HTTP base URL, `http://` or `https://`, such as `https://collector.example:4318`. goethite appends `/v1/metrics`. |
| `headers_file` | unset | A file of `Name: value` lines sent as headers with every export, such as an API key: at most 16 headers and 8 KiB. Blank lines and lines starting with `#` are skipped. |
| `ca_file` | unset | CA certificates (PEM) to verify the collector with, instead of the public roots. |
| `metrics` | `true` | Whether the metrics are sent. |
| `interval` | `60` | Seconds between exports, 10 to 3600. |

goethite resolves the collector's name through its own upstreams and
[local records](../local-records/), not the system's resolver: use an address, or a name those
answer. `headers_file` and `ca_file` are read before goethite drops its privileges, so they may be
readable by root only. Over plain HTTP beyond loopback, goethite warns that the metrics and the
headers can be read on the way.

## Logging

Logs go to standard error, and the `RUST_LOG` environment variable sets the level (default
`info`). For example, `RUST_LOG=debug` shows dropped and rejected packets, and
`RUST_LOG=goethite_resolver=debug` shows only the resolver's details. Two libraries say less
unless `RUST_LOG` names them, since goethite reports what they would itself: hickory-proto, which
would quote malformed packets, is off, and openraft, which logs every election and membership
change, logs warnings only (`RUST_LOG=info,openraft=info` shows them).
