# ADR 0014: The Terraform provider

- **Status:** Superseded by [ADR 0034](0034-drop-the-terraform-provider.md)
- **Date:** 2026-10-08

## Context

Phase 3.5 is a Terraform provider, in its own repository (`terraform-provider-goethite`, Go,
terraform-plugin-framework), built from the OpenAPI document. goethite's API already had what a
provider needs: resources with IDs, specs, revisions as ETags, `If-Match`, a stable error format,
and `managed_by`, which the TUI and web UI treat as read-only for `terraform`.

## Decision

**The client is generated from goethite's `openapi.json`.** The provider keeps a copy, with the
goethite commit it came from, and `go generate` turns it into Go types and a client with
oapi-codegen. oapi-codegen reads OpenAPI 3.0, and goethite publishes 3.1, so a small tool
converts it first: nullable types, nullable references and references with a description are the
only 3.1 forms goethite uses. A thin hand-written layer turns goethite's error answers into Go
errors. CI regenerates the client and fails on any difference, and the acceptance tests build
goethite from that same commit.

**Revisions live in Terraform's private state.** Every update and delete sends the revision
Terraform last read as `If-Match`. A change made between refresh and apply fails with an
explanation instead of being overwritten, and revisions never clutter plans.

**`managed_by` always plans `terraform`.** It is a computed attribute whose plan is always
`terraform`, so importing a resource someone made in the TUI shows the takeover in the plan, and
the apply makes it read-only elsewhere.

**Two resources that always exist** behave as Terraform users expect of such things:

- the default group is imported as `default`; destroying it resets it to how goethite creates
  it, since goethite refuses to delete it;
- `goethite_settings` manages only the attributes set, and destroying it leaves the settings as
  they are.

**goethite stays the judge of what is valid.** Validators catch obvious mistakes at plan time
(exactly one of `url` and `path`, weekday names, ranges); goethite's answers explain the rest,
so the two cannot disagree about a rule's syntax or a time zone.

**Acceptance tests run Terraform and OpenTofu against a real goethite**, which they start with
an admin token on a free port. They cover create, import, update, drift, takeover, the default
group, settings and goethite's own refusals.

## Consequences

- A new goethite API version reaches the provider by copying one file and running
  `go generate`; a breaking change shows up as a compile error or a failing acceptance test.
- The provider works against either node of a cluster: verified by hand, including a failed
  apply with goethite's explanation while the primary was down.
- Until it is on the Terraform Registry, which needs signed releases (Phase 5), it is installed
  from source with `dev_overrides`.
- govulncheck runs in the provider's CI. It found a reachable gRPC vulnerability through the
  plugin framework at the start, fixed by upgrading gRPC.

## Alternatives considered

- **A hand-written client.** One dependency fewer, but nothing would tie it to the API it talks
  to. Declined.
- **The revision as a regular attribute.** Every update would show it changing in the plan.
- **Settings defaults on every attribute.** Applying a configuration that sets one value would
  reset the others.
