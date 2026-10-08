---
title: Web UI
description: Watch a goethite node from a browser.
---

goethite serves a web UI next to its [REST API](../api/), on the same addresses. On the machine
running goethite, open:

```
http://127.0.0.1:8053/
```

It shows the dashboard and the query log. More screens arrive with goethite 0.4; until then,
lists, rules, clients and groups are changed through the API or the [terminal UI](../tui/).

## Signing in

A node without an admin token answers loopback only and needs no sign-in. Reach it from another
machine through an SSH tunnel, then open `http://localhost:8053/`:

```sh
ssh -L 8053:127.0.0.1:8053 dns.example.lan
```

A node with a token (see [REST API](../api/#access)) asks for it on the sign-in page. The token
stays in that browser tab only and is forgotten when the tab closes, on sign-out, or when the node
stops accepting it. Serve the API over HTTPS (`tls_cert` and `tls_key`) when you use it across
the network; otherwise the token crosses it in clear text.

## Screens

- **Dashboard**: the last 24 hours (queries, blocked, cached, forwarded, failed, average answer
  time), queries per hour, the top blocked names, names and clients, each upstream's health, the
  filter and its lists, and the node's cache and query log. The header shows whether filtering is
  on, and pauses it for 10 minutes or resumes it. In a [cluster](../ha/), the counts are both
  nodes' together, the header shows this node's role and its peer, a Cluster panel says whether
  changes are possible, and cluster problems appear at the top.
- **Query log**: the newest queries, following new ones live, with the client, the answer and
  what decided it (the rule, a CNAME, the upstream). Search by name and by answer, and page back
  through older entries. Searches are part of the address, so they can be bookmarked.

Every answer carries a text label (`BLOCKED`, `CACHED`, `FORWARDED` and so on), so nothing
depends on color alone. The theme follows the system; the header switches it.

## Security

The UI runs under a strict Content Security Policy: no inline code, nothing from other sites, not
even fonts. Its files need no token, but everything they show comes from the API, which does.
The API refuses requests from other web sites and, without a token, requests that do not name
this machine, so pages you visit cannot use your browser against it. See
[ADR 0009](https://github.com/nxplain-sh/goethite/blob/main/docs/adr/0009-web-ui-serving.md).

To turn the UI off and keep only the API:

```toml
[api]
web_ui = false
```

Builds made without the UI (see [Install](../install/#build)) log that they have none.
