# ADR 0033: License goethite under the AGPL-3.0-only, with contributions under Apache-2.0

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

goethite has been MIT OR Apache-2.0 since its first commit, the Rust default. The plan for later
is two offerings from one code base: goethite to self-host, free, and a paid hosted service run by
the maintainers. A permissive license also lets anyone else sell goethite as a hosted service,
with changes they never publish.

Every commit so far is the maintainer's own, apart from Renovate's version bumps, so the license
can still change without asking anyone. Each release under MIT OR Apache-2.0 makes a change more
expensive: that release stays available under those terms for good, and a fork can start from it.

## Decision

**goethite is licensed under the GNU Affero General Public License, version 3 only, from the
release after v0.5.0.** One `LICENSE` file replaces `LICENSE-MIT` and `LICENSE-APACHE`. The
crates, the web UI, the site, the packages, the container image and the OpenAPI document say
`AGPL-3.0-only`.

**Contributions come in under Apache-2.0.** The README says so where it used to say that
contributions were dual licensed. goethite ships them under the AGPL with the rest of the code.
The Apache-2.0 grant also lets the maintainers offer goethite under other terms, such as a hosted
service with closed parts or a commercial license for companies that do not take AGPL code,
without a contributor license agreement.

**Dependencies stay permissive.** `deny.toml` and cargo-about (`xtask/dist/about.toml`) keep their
allow lists, and now skip goethite's own crates (`publish = false`) instead of checking them
against those lists. A copyleft dependency, or bundled copyleft data such as AdGuard's GPL-3.0
service catalog ([ADR 0019](0019-blocked-services.md)), would hold every copy of goethite to
copyleft terms, the maintainers' own included, and close off the other terms.

**The Terraform provider keeps MIT OR Apache-2.0.** It is a separate program that talks to the API
over HTTP. Terraform users expect a permissive provider, and it gives a competing hosted service
nothing it could not get from the API documentation.

## Alternatives considered

- **Stay MIT OR Apache-2.0.** Widest adoption, and no friction with company legal teams. A hosted
  DNS filtering service competes mostly on operations (network, uptime, privacy), not code. But
  anyone stays free to sell goethite hosted, closed changes included. Revisit if the AGPL keeps
  companies from adopting the self-hosted version.
- **A source-available license** (Functional Source License, Business Source License, Elastic
  License 2.0). These forbid a competing hosted service outright, but they are not open source:
  no OSI approval, no Debian or Fedora packages, and at odds with nxplain.sh as an open source org.
  Moving a project with users to one has started forks (Terraform and OpenTofu).
- **GPL-3.0.** Its conditions apply when the program is distributed, and a hosted service does not
  distribute it: a competitor could run a changed goethite as a service and share none of it.
- **AGPL-3.0-or-later.** Would let a future AGPL version, written by the FSF, apply to goethite.
  With contributions under Apache-2.0, the maintainers can still move to a later version;
  `-only` keeps that choice theirs.
- **A contributor license agreement.** Gives the maintainers the same freedom, but needs a
  signature from every contributor and a bot to collect it: a barrier the Apache-2.0 grant avoids.
- **Keep the reusable crates permissive** (`goethite-proto`, `goethite-filter`) and license only
  the program under the AGPL. None is published to crates.io or used outside goethite, and one
  license is simpler to explain. Revisit when a crate is published.

## Consequences

- v0.5.0 and every release before it stay MIT OR Apache-2.0. Only later releases are AGPL.
- Anyone who distributes goethite, or runs a changed version that others use over a network, must
  offer those people the source of that version. For a DNS server, the network users include
  every client that queries it: a company that patches goethite owes the patch to its own staff.
- Some companies forbid AGPL software. They will skip the self-hosted version or need a commercial
  license.
- Contributors keep their copyright and grant Apache-2.0. A contribution offered under other
  terms has to say so, and the maintainers can decline it.
- cargo-deny and cargo-about no longer check goethite's own crates. Publishing one to crates.io
  removes the `publish = false` the skip relies on, so that crate is checked again and needs an
  exception for `AGPL-3.0-only`.
