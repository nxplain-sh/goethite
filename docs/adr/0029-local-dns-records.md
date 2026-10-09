# ADR 0029: Local DNS records, answered before the filter

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

Until v0.4 goethite answered only its built-in names (`goethite.test`) itself. Pi-hole's local DNS
and CNAME records and AdGuard Home's DNS rewrites are among the features home networks rely on
most: a name for the storage box, or every name behind a reverse proxy. The importers (v0.5)
would lose them without a place to put them, and the resolution pipeline in `AGENTS.md` already
has a stage for them: local rewrites, after client identification and before the filter.

## Decision

**Local records are a replicated resource (`records`, IDs `rc_…`), compiled into the policy and
answered right after the built-in names, before the filter, for every client.**

- **Types:** `A`, `AAAA` and `CNAME`, each with a TTL (300 s by default, at most a day). A name
  is exact (`nas.lan`) or a wildcard for every name below one (`*.home.example`, not the name
  itself). An exact name wins over a wildcard and a closer wildcard over one further up.
- **Answers:** a name with records answers only from them, NODATA for other types, with the AA
  flag, logged as `local`. A `CNAME` is followed through the local records; where it leaves them,
  the target is resolved by the rest of the pipeline (filter, safe search, cache, upstreams), so a
  `CNAME` to a blocked name is blocked and CNAME uncloaking still holds. Local `CNAME` loops and
  chains longer than the cache's `MAX_CNAME_CHAIN` get `SERVFAIL`.
- **Not filtered, not grouped:** records are the network's own names, so they answer whatever
  the client's group, and while filtering is off or paused. They are applied before rebinding
  protection, which only checks upstream answers: private addresses for local names are the
  point.
- **Validation:** names must parse and may not be under `goethite.test`; values must match the
  type; no record twice; a name with an enabled `CNAME` has no other enabled record; at most
  10,000.
- **Schema 2:** the store gains a `records` table, created when an older store is opened, and
  the schema version, which a replica checks, becomes 2. A replica that copied from a primary of
  the other version would otherwise drop the records silently (an older one) or fail to decode
  them (a newer one); now both say the versions differ, as the HA guide describes.

## Alternatives considered

- **Hosts-file lines in the filter lists as records:** the lists are third-party data; letting a
  downloaded list answer names with addresses is a much larger trust decision. Kept separate
  (backlog).
- **Records per group:** possible later; no importer source needs them, and one view of the
  network's own names is simpler to reason about.
- **More types (TXT, MX, SRV, PTR):** not needed for what home networks and the importers use;
  automatic PTR answers for `A` records are backlog.
- **Answering the `CNAME` alone** and leaving the target to the client: stub resolvers expect the
  chain resolved, and the filter would not see the target.

## Consequences

- The web UI has a Records page and the API `/api/v1/records`; the TUI and the Terraform provider
  do not list records yet (backlog).
- A cluster needs both nodes on the same version to keep copying, as before any schema change.
