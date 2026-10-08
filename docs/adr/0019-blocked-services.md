# ADR 0019: Blocked services

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

AdGuard Home lets a group block a service, such as TikTok, YouTube or Roblox, with one toggle,
always or on a schedule, without anyone knowing which of its dozens of domains to block. The user
asked what goethite could take from GoodbyeAds, AdGuard's HostlistsRegistry, dnswarden and HaGeZi,
and chose this. The rules behind the toggles are AdGuard's: HostlistsRegistry publishes them as
`services.json`, 142 services with 2,406 adblock-style rules, under GPL-3.0. goethite is MIT OR
Apache-2.0.

## Decision

**The catalog is downloaded, not bundled.** The node downloads
`https://adguardteam.github.io/HostlistsRegistry/assets/services.json` with the filter lists, into
the list cache, where it replaces the last good copy only if it reads as a catalog; a restart works
offline with the copy it has. No GPL-3.0 data is compiled into goethite. `[filter] services =
false` turns blocked services off, and `services_file` reads the catalog from a file instead, for
nodes that cannot reach the internet. `GET /api/v1/services` serves the catalog, with the rules
goethite uses, the source and its license.

**Read without trust.** The parser (`goethite_api::services`, fuzzed by `parse_services`) ignores
unknown fields (the icons), keeps services with valid, distinct IDs, cuts names, caps the services
(1,024), the rules per service (2,048) and each rule's length (1,024 bytes), and refuses a catalog
larger than 4 MiB or with no services. Rules go through goethite's own rule parser; only blocking
rules it reads are kept. Today that is 141 services and 2,378 rules: wildcards inside domain
names, `$dnstype` and `$dnsrewrite` rules are left out, and with them iCloud Private Relay, whose
rules are all `$dnsrewrite`. Leaving a rule out blocks less, never more.

**Groups name services by ID.** A group's `blocked_services` holds `{service, schedule}` entries,
like its `lists`, so a service is blocked always or while a schedule is active. The store checks
an ID's syntax but not whether the catalog has it: the catalog is downloaded and may not be there
yet, and a Terraform plan must not depend on it. An ID the catalog does not have blocks nothing,
and the web UI says so.

**Compiled like lists, checked first.** The catalog is compiled into `goethite_filter` filters of
64 services each, one source per service, so a block still says which service and rule did it.
A group holds a fixed-size bitset of up to 1,024 services, so checking a query allocates nothing.
Blocked services are checked before the group's lists and custom rules: a group that blocks
TikTok blocks it whatever an exception in a list says. They follow the same switches as the rest
of filtering (protection, pause, the group's `filtering`), and check the name asked for, not
CNAME targets, since services' own CDNs are often shared. The query log records the source as
`service:<id>`.

## Consequences

- goethite contacts `adguardteam.github.io` when lists are refreshed, unless turned off; documented
  under Security.
- The catalog's rules change without a goethite release, like a list's.
- The Terraform provider can manage `blocked_services` once it is generated from the new API.
- `$dnsrewrite=NXDOMAIN` rules, which only block, could be read later; iCloud Private Relay would
  then come back.
