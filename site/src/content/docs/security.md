---
title: Security settings
description: DNS rebinding protection, rate limiting, connection limits, privilege dropping, and the API.
---

goethite is built to be safe by default: the protections on this page are on unless you turn them
off. The [threat model](https://github.com/nxplain-sh/goethite/blob/main/docs/THREAT_MODEL.md)
lists every threat and what defends against it.

## DNS rebinding protection

In a DNS rebinding attack, a web page from a name the attacker controls makes that name resolve to
an address inside your network, such as your router's `192.168.1.1`. The browser still thinks it is
talking to the attacker's site, so the page can reach devices that were never meant to be exposed
to the internet.

goethite removes such answers: when a forwarded answer for a public name contains an A or AAAA
record with a private address, that record is dropped before the answer is cached or sent. These
addresses count as private:

| Range | What it is |
| --- | --- |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private IPv4 networks (RFC 1918) |
| `100.64.0.0/10` | carrier-grade NAT (RFC 6598) |
| `127.0.0.0/8`, `::1` | loopback |
| `169.254.0.0/16`, `fe80::/10` | link-local |
| `0.0.0.0/8`, `::` | "this host" and unspecified |
| `fc00::/7` | unique local IPv6 (RFC 4193) |

IPv4 addresses mapped into IPv6 (`::ffff:192.168.1.1`) are checked as IPv4. The question name
decides, not the names in the answer: a public name that is a CNAME for `printer.lan` still loses
its private addresses.

Names below the private domains may resolve to private addresses, so a local DNS server behind
goethite keeps working for them:

```toml
[security]
rebinding_protection = true
private_domains = ["lan", "home.arpa", "internal", "local"]   # the defaults
```

Add your own domains to `private_domains` if a public domain you own resolves to internal addresses
(split-horizon DNS), for example `private_domains = ["lan", "home.arpa", "corp.example"]`. Setting
`private_domains` replaces the defaults, so list them again if you still want them. Answers
goethite gives itself, such as blocked names answered with `0.0.0.0`, are never touched.

## Rate limiting

A resolver that answers anyone can be abused to flood a third party: an attacker sends small
queries with the victim's address as the source, and the resolver sends the larger answers to the
victim. goethite limits how many UDP queries each client network may send, before resolving them,
so a flood also never reaches the cache or the upstreams:

```toml
[server.rate_limit]
queries_per_second = 300   # on average, per client network; 0 turns rate limiting off
burst = 1000               # queries a quiet client may send at once
slip = 2                   # see below
ipv4_prefix = 32           # each IPv4 address is its own client network
ipv6_prefix = 64           # each IPv6 /64 is one client network
max_clients = 65536        # client networks tracked at once
```

These are the defaults, generous enough for a busy network behind one router. Queries over the
limit are dropped, except every `slip`-th one, which gets an empty answer with the truncated (TC)
flag set. A real client then retries over TCP, which is not rate limited (a TCP client has proven
its address with the handshake), while a spoofed victim gets nothing bigger than the query. `slip
= 0` drops every limited query; `slip = 1` answers each one with TC.

Clients on loopback are never limited: their addresses cannot be spoofed from the network, and a
local stub resolver (systemd-resolved, dnsmasq) may forward every query of the host. When more
client networks are active than `max_clients`, the networks that are not tracked share one limit.

Rate limiting is a safety net, not a firewall: do not expose goethite to the internet unless you
mean to run a public resolver. To reach it from outside, serve
[DNS over TLS, HTTPS or QUIC](../encrypted-dns/#reaching-goethite-from-the-internet) with
`require_client_id = true` instead of port 53.

## Connection limits

goethite serves at most 256 TCP connections at once, and at most 16 from one client (an IPv4
address or an IPv6 /64), so a single host cannot take every connection. DNS over TLS, HTTPS and
QUIC connections count against the same limits; a QUIC client's address is checked with a Retry
first, so forged packets cannot take a connection. A TCP connection that sends nothing for 10
seconds is closed; an encrypted one after 30 seconds, and its TLS handshake must finish within
10.

```toml
[server]
max_tcp_connections = 256
max_tcp_connections_per_client = 16
```

## Privileges

goethite needs privileges only to bind port 53. It binds its sockets first, before starting any
thread, then gives the privileges up:

- **Under systemd**, with the unit in
  [`dist/systemd/goethite.service`](https://github.com/nxplain-sh/goethite/blob/main/dist/systemd/goethite.service),
  goethite runs as a dynamic, unprivileged user that may only bind ports below 1024, and gives that
  up once its sockets are bound. The unit also makes the file system read-only except
  `/var/lib/goethite` (keep downloaded lists there with `cache_dir = "/var/lib/goethite/lists"`),
  hides other processes and devices, allows only IP sockets and filters system calls.
  `systemd-analyze security goethite` rates it 1.7, "OK"; what remains is what a DNS server needs,
  such as Internet sockets.
- **Started as root** without systemd, set the user to switch to:

  ```toml
  [server]
  user = "goethite"   # looked up in /etc/passwd
  ```

  goethite switches to that user and its primary group, drops supplementary groups, and checks
  that it cannot become root again. Started as root without `user`, it logs a warning.

Either way, goethite then empties its capability sets and sets `no_new_privs`, so it cannot gain
privileges again, even by running a program. The filter lists and their `cache_dir` must be
readable, and the `cache_dir` writable, by the user goethite runs as. Dropping privileges is
supported on Linux; on other platforms, which are for development only, `server.user` is an error.

A [floating IP](../ha/#a-floating-ip) needs privileges the DNS server never gets, so a separate
process holds them: `goethite vrrp`, under
[`dist/systemd/goethite-vrrp.service`](https://github.com/nxplain-sh/goethite/blob/main/dist/systemd/goethite-vrrp.service).
It starts with `CAP_NET_RAW` and `CAP_NET_ADMIN`, opens its raw sockets, then keeps only
`CAP_NET_ADMIN` (to add and remove the address) and sets `no_new_privs`. Its sandbox matches the
DNS server's, with netlink and packet sockets allowed and nothing writable;
`systemd-analyze security goethite-vrrp` rates it 1.9, "OK".

## The API, the web UI and the logs

- **Admin token.** Without one, the [REST API](../api/) answers loopback only and refuses to listen
  anywhere else. The config holds only the token's SHA-256 hash. Beyond loopback, serve HTTPS
  (`tls_cert`, `tls_key`); over plain HTTP goethite warns that the token can be sniffed.
- **Browsers.** The API refuses requests from other web sites and, without a token, requests that
  do not name this machine, so pages you visit cannot use your browser against it (including by
  DNS rebinding). The [web UI](../web-ui/) runs under a strict Content Security Policy and keeps
  the token in its browser tab only. `[api] web_ui = false` turns it off.
- **API reference.** `/api/docs` is off unless `[api] docs` turns it on, answers loopback only,
  and serves files built into goethite. Its scripts are limited to goethite's own, like the UI's;
  see [Web UI](../web-ui/#api-reference) for its style policy.
- **Limits.** At most 64 API connections, 10 seconds for the TLS handshake and headers, 1 MiB
  request bodies and 30 seconds per request.
- **Audit log.** Every change to lists, rules, groups, clients, schedules and settings is recorded
  with who made it, from where, and the before and after (`GET /api/v1/audit`).
- **Query privacy.** The [query log](../configuration/#querylog) keeps 7 days by default, can
  shorten client addresses to their /24 and /56 (`anonymize_clients = true`) or be turned off. The
  store file is readable by goethite's user only.

## Connections goethite makes

goethite opens connections only to:

- the **upstream resolvers** in `[[upstream]]`, for the queries it forwards; or, with
  [recursion](../recursion/), the **root servers and the authoritative servers** of the names
  looked up, each shown only as much of a name as it needs;
- the hosts of **downloaded filter lists**, over HTTPS, when lists are refreshed (by default
  every 24 hours), including the [default lists](../filtering/#recommended-lists-and-presets) of
  a new node; and the hosts of the recommended lists, for the first 8 KiB of each, when someone
  opens the Lists page, at most once a day (`[filter] directory = false` turns it off);
- **`adguardteam.github.io`**, over HTTPS, for the [blocked services](../groups/#blocked-services)
  catalog, when lists are refreshed (`[filter] services = false` turns it off, `services_file`
  reads it from a file instead);
- **`api.filterlists.com`**, over HTTPS, only when someone opens Find lists in the web UI, at
  most once a day ([FilterLists directory](../filtering/#finding-more-lists); `[filter]
  directory = false` turns it off);
- its **cluster peer**, if it has one.

Names are resolved through goethite's own upstreams. The web UI's pages talk to goethite only;
links to list home pages open in a new tab.

## When filtering fails

goethite answers every query on your network, so by default a failure in filtering never stops
it from answering ("fail open"):

- If its store file cannot be opened (but is not just in use by another goethite), it runs on a
  temporary store in memory, seeded from the config file's `[filter]` table, and leaves the file
  alone for you to look at.
- If the filter cannot be built, it starts unfiltered; later, a filter that cannot be rebuilt
  leaves the previous one in place.
- If checking a name fails (a bug), that query is answered unfiltered.

Each of these appears in `problems` in `GET /api/v1/status`, in the TUI and the web UI, and as
`goethite_degraded 1` in the metrics; failed checks are counted in
`goethite_filter_failures_total`.

Where unfiltered answers are worse than none, fail closed instead:

```toml
[filter]
on_failure = "closed"
```

goethite then refuses to start with a broken store or filter, and answers SERVFAIL to a query
whose check failed.
