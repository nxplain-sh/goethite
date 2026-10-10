# ADR 0034: Drop the Terraform provider and the `terraform` value of `managed_by`

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

[ADR 0014](0014-terraform-provider.md) added a Terraform and OpenTofu provider in its own
repository, `terraform-provider-goethite`. That repository has been removed: goethite has no
provider, and none is planned for 1.0. Terraform stays a possible later feature.

goethite still carried the provider's side of the contract: a `terraform` value of `managed_by`
in the API and the store, which the web UI and the TUI showed read-only, with notes to "change it
in Terraform". Nothing sets that value any more, except a client that sends it by hand, and then
the UIs point at a tool that does not exist.

## Decision

**`managed_by` is `api` or `config_file`.** The `terraform` value is gone from the API and the
OpenAPI document. goethite reads `terraform` as `api`, from the store, from the Raft log and from
requests, so stores written by earlier versions open as before.

**Nothing is read-only in the web UI and the TUI.** The read-only notes, the disabled fields and
buttons, and the checks that kept the web UI from changing a group Terraform managed are removed.
The `CONFIG FILE` badge and its note stay.

**Terraform is mentioned only as a possible later feature**, in the
[backlog](../BACKLOG.md) and in the out-of-scope list in `AGENTS.md`. The website's Terraform
guide is removed. ADRs and released changelog entries keep what they said at the time.

## Alternatives considered

- **Keep the `terraform` value and the read-only handling for a future provider.** Code and tests
  for something nothing uses, and UI text that sends people to a provider that does not exist. A
  future provider can bring its value back in one change, and may want a different design.
- **Rename it to a generic value**, such as `external`, read-only for any tool. That designs for a
  use nobody has asked for yet; it can be added when there is one.
- **Remove the value without the alias.** Simpler, but a store holding `terraform` would fail to
  load. The alias costs one attribute.

## Consequences

- Removing an enum value from `/api/v1` is a breaking change by oasdiff's rules, so the pull
  request carries the `api-breaking` label. Clients that send `terraform` keep working; they get
  `api` back.
- Resources a provider created become editable in the web UI and the TUI on upgrade.
- The audit log keeps `terraform` in the before and after of old entries: it records what was
  stored then.
- [ADR 0033](0033-agpl-license.md)'s note that the provider keeps MIT OR Apache-2.0 no longer
  applies to anything; a new provider would decide its license again.
