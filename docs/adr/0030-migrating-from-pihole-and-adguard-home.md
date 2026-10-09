# ADR 0030: Migrating from Pi-hole and AdGuard Home through their APIs

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

Most people who would run goethite run Pi-hole or AdGuard Home today. Rebuilding their lists,
groups, clients and local names by hand is the largest cost of switching. Both projects keep their
configuration in formats goethite would need new parsers, and new dependencies, to read: Pi-hole a
SQLite database (`gravity.db`) and a TOML file, AdGuard Home a YAML file. Both also serve the whole
configuration as JSON over their web APIs: Pi-hole v6 at `/api`, AdGuard Home at `/control`.

## Decision

**`goethite migrate pihole|adguard-home` reads the running server's web API, plans the same
configuration in goethite, prints the plan, and with `--apply` makes it through goethite's API.**

- **Sources:** Pi-hole v6 (session from `POST /api/auth`, sent as `X-FTL-SID`, logged out at the
  end, since Pi-hole keeps few sessions) and AdGuard Home (HTTP Basic, no cookies). JSON only, read
  with serde: no SQLite or YAML dependency. The API facts were checked against both projects'
  source (Pi-hole FTL v6.7.1, AdGuard Home v0.107.79), including their quirks: AdGuard's empty
  arrays as `null`, Pi-hole's dnsmasq CNAME syntax, AdGuard's blocked-service schedule as pauses.
- **A pure plan:** `goethite-migrate` turns the answers into a plan with no network access, and
  checks every planned resource the way the store would, so a plan never holds what goethite
  refuses. Each left-out item comes with its reason, and each difference in behaviour with a note.
  The plan is fuzzed (`plan-migration`).
- **Applied through the API, not the store:** goethite keeps running, every change is validated,
  audit-logged and replicated, and the command works against a remote node with a token.
- **Additive and repeatable:** a list with the same URL, a group or client with the same name, the
  same rule or record is kept. A second run changes nothing; the old server is never changed.
- **Mappings worth recording:** Pi-hole's Default group is goethite's default group; its other
  groups become groups, and exact domains become rules for every group (goethite's rules have no
  groups). AdGuard Home's per-client settings become a group per client. Rewrites and Pi-hole's
  local DNS and CNAME records become local records ([ADR 0029](0029-local-dns-records.md)).

## Alternatives considered

- **Reading the files (`gravity.db`, `pihole.toml`, `AdGuardHome.yaml`):** works with the old
  server stopped, but needs a SQLite crate (with its C library) and a YAML crate, and tracks
  on-disk formats the projects do not promise to keep.
- **Writing the store directly:** needs goethite stopped, bypasses the audit log and the API's
  checks, and does not reach the other node of a cluster.
- **Replacing goethite's configuration with the old one:** destructive; adding what is missing is
  safer and makes the command repeatable.

## Consequences

- The source must be running and reachable from where the command runs, with its password.
- Pi-hole v5 is not supported (its API is different); upgrading Pi-hole to v6 first works.
- Things goethite lacks stay behind, listed in the plan: regular expressions, allowlist
  subscriptions, MAC and host name clients, upstreams per domain, AdGuard's own services.
