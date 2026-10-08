---
title: Web UI
description: Watch and configure a goethite node from a browser.
---

goethite serves a web UI next to its [REST API](../api/), on the same addresses. On the machine
running goethite, open:

```
http://127.0.0.1:8053/
```

It shows what goethite is doing and changes everything the [REST API](../api/) can: lists,
rules, groups, clients, schedules and settings.

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
- **Lists**: every filter list with its rule count and any problem, and a button to download
  them all again now. A new list can join the default group at once, so it filters straight
  away.
- **Rules**: custom rules, added from the top of the page, filtered as you type, turned on and
  off in place. goethite explains a rule it cannot use.
- **Groups**: which lists filter a group's clients, each always or during a schedule, and safe
  search.
- **Clients**: devices and networks by address, and their group.
- **Schedules**: weekly windows in a time zone; a window can run past midnight.
- **Settings**: filtering on or off, how blocked names are answered, and how often lists are
  downloaded.
- **Audit log**: who changed what, from where, with the resource before and after.

Changes are made with the revision you saw: if someone else changed the same thing meanwhile, the
UI says so and offers their version instead of overwriting it. What [Terraform](../terraform/)
manages is shown read-only, with a note to change it there. A list, schedule or group that
something still uses says what: deleting a list takes it out of the groups that use it, while a
schedule or a group can only go once nothing uses it.

Every answer carries a text label (`BLOCKED`, `CACHED`, `FORWARDED` and so on), so nothing
depends on color alone. The UI has one theme, light.

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

## API reference

goethite can serve its API reference, rendered from its own OpenAPI document, at `/api/docs`:

```toml
[api]
docs = true
```

It answers loopback clients only (use an SSH tunnel from elsewhere) and needs no token: it
describes the API, not your data, as the [reference on this site](../api-reference/) does. Its
files are built into goethite. Its policy differs from the UI's in styles only: style elements
need a fresh nonce or a known hash, and style attributes are allowed, since the reference sets
sizes in them; scripts stay limited to goethite's own files.
