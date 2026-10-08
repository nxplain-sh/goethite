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

- **Dashboard**: the last 24 hours, 7 days or 30 days (queries, blocked, cached, forwarded,
  failed, average answer time), a chart of queries per hour, 6 hours or day, the top blocked
  names, names and clients, each upstream's health, the filter and its lists, and the node's cache
  and query log. Everything leads to its queries: a tile opens the query log for that answer, a
  name or client in a top list for that name or client, and a bar of the chart (hover or focus it
  for its counts) for its time window. A top blocked name can be allowed, and a top name blocked,
  in two clicks: that adds a custom rule. The range is part of the address. The header shows
  whether filtering is on, and pauses it for 10 minutes or resumes it. In a [cluster](../ha/), the counts are both
  nodes' together, the header shows this node's role and its peer, a Cluster panel says whether
  changes are possible, and cluster problems appear at the top.
- **Query log**: the newest queries, following new ones live, with the client, the answer and
  what decided it (the rule, a CNAME, the upstream). Search by name and by answer, and page back
  through older entries. Filters set from the dashboard (a client, a time window) show as chips
  to remove. Searches are part of the address, so they can be bookmarked.
- **Lists**: every filter list with its rule count, the lines it skipped and any problem, and a
  button to download them all again now. A new list can join the default group at once, so it
  filters straight away. [Recommended lists](../filtering/#recommended-lists-and-presets) are
  shown by category with their sizes and add in a click; **presets** set a group's lists in one
  step after showing what changes; lists that do the same job switch rather than stack; and
  **Find lists** searches the [FilterLists directory](../filtering/#finding-more-lists).
- **Rules**: custom rules, added from the top of the page, filtered as you type, turned on and
  off in place. goethite explains a rule it cannot use.
- **Groups**: which lists and [blocked services](../groups/#blocked-services) filter a group's
  clients, each always or during a schedule, and safe
  search.
- **Clients**: devices and networks by address or [client ID](../encrypted-dns/#client-ids), and
  their group. With an ID, the editor shows the DNS over HTTPS URL and the DNS over TLS and QUIC
  names to set the device up with.
- **Schedules**: weekly windows in a time zone; a window can run past midnight.
- **Audit log**: who changed what, from where, with the resource before and after.
- **Leak test**: whether this device's lookups reach goethite, over which protocol and as which
  client, or go to another resolver past its filtering; see [DNS leak test](../leak-test/).
- **Settings**, in the header beside Pause and Sign out: filtering on or off, how blocked names
  are answered, and how often lists are downloaded.

Changes are made with the revision you saw: if someone else changed the same thing meanwhile, the
UI says so and offers their version instead of overwriting it. What [Terraform](../terraform/)
manages is shown read-only, with a note to change it there. A list, schedule or group that
something still uses says what: deleting a list takes it out of the groups that use it, while a
schedule or a group can only go once nothing uses it.

Every answer carries a text label (`BLOCKED`, `CACHED`, `FORWARDED` and so on), so nothing
depends on color alone. The UI has one theme, light.

## Security

The UI runs under a strict Content Security Policy: no inline code, nothing from other sites, not
even fonts. The one exception: images from `*.leak.goethite.test`, names only goethite answers,
which the [leak test](../leak-test/) has the browser look up. Its files need no token, but everything they show comes from the API, which does.
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
