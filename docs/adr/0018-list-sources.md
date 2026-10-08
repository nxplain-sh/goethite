# ADR 0018: Where filter lists come from

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

A new goethite filtered nothing until someone found a list and pasted its address. AdGuard Home
and Pi-hole start with a list, and offer more. The user asked for a set of recommended lists, a
default, and a way to find lists through [FilterLists](https://filterlists.com), an MIT-licensed
directory of 2,321 lists with a public JSON API (1,135 of them in syntaxes goethite reads).

## Decision

**A recommended set, built in and checked.** `GET /api/v1/lists/recommended` returns ten lists
for ads and trackers (HaGeZi Multi Light, Normal, Pro and Pro++, AdGuard DNS filter, OISD Small
and Big, Steven Black's hosts, AdAway, Peter Lowe's list). Each was downloaded and parsed by
goethite: none has an invalid line, and only AdGuard's has lines goethite skips (554 `$modifier`
rules of 179,000). Licenses come from each project's own license file; FilterLists' data was
out of date for two of them. The web UI adds one in a click, to the default group.

**One default, for new nodes only.** The first start of a new store adds HaGeZi Multi Normal to
the default group: an all-round list made for DNS blocking, with few false positives. It is an
ordinary list, so it can be removed, replaced or managed by Terraform like any other, and
`goethite import` leaves it alone. A config file that names `[[filter.list]]` entries, or sets
`[filter] default_lists = false`, gets none; existing nodes never change.

**The FilterLists directory, through the node.** `GET /api/v1/lists/directory` and
`/api/v1/lists/directory/{id}` serve the directory, fetched by the node from
`api.filterlists.com` only when someone browses it, never by the browser (whose CSP allows only
goethite). Requests go over HTTPS through goethite's own resolver, at most 4 MiB and 20 seconds
each; the directory and up to 256 lists' details are kept for a day, and one refresh runs at a
time. The answers are third-party data, read by bounded parsers (`goethite_api::catalog`,
fuzzed by `parse_filterlists`): unknown fields ignored, text stripped of control characters and
cut short, counts capped, only `https://` addresses kept. Lists in syntaxes goethite cannot read
are left out, and so are allowlists: their plain domains are meant to be allowed, and goethite
would block them. Adding a list from the directory opens the usual form, filled in, so a person
checks it before it filters anyone. `[filter] directory = false` turns the directory off.

## Consequences

- A new node filters ads and trackers from its first minute, if it can download the list; until
  then (or offline) it answers unfiltered by that list, as with any list not yet downloaded.
- goethite contacts `api.filterlists.com` only when someone opens the directory, and the list
  hosts people choose. Both are documented under Security.
- The recommended set and its rule counts need a look at each release: lists move and grow.
