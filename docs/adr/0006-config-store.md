# ADR 0006: The store is the source of truth for filtering configuration

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

From Phase 2 on, filtering configuration (lists, custom rules, groups, clients, schedules and
the filtering settings) is changed at run time through the API, the TUI, the web UI and later
Terraform. Phase 3 replicates it across nodes. Phase 1 read the same things from the TOML config
file. AGENTS.md says the replicated config store is authoritative and TOML is for bootstrap.
Every change must be audit-logged.

## Decision

- **One embedded database file** (redb), `goethite.redb` in the state directory, holds the
  configuration resources, the settings and the audit log, and later the query log and
  statistics. It is created with mode 0600 and locked against a second process.
- **The store is authoritative.** The TOML `[filter]` table seeds an empty store on the first
  start, and a fingerprint of what was imported is recorded. If the table changes later, goethite
  warns and keeps the store as it is. `goethite import` (with goethite stopped) applies the
  table again: it replaces the lists and rules marked `managed_by = "config_file"`, keeps those
  from the API or Terraform, adds new lists to the default group and removes deleted ones from
  every group. Imported resources get IDs derived from their content, so importing twice changes
  nothing. Node settings (listen addresses, upstreams, cache, store path, API) stay in TOML.
- **Resources** have a generated ID, a revision, timestamps and a spec. Specs reject unknown
  fields. Responses nest the spec under `spec`, because serde cannot reject unknown fields in a
  flattened struct. Updates and deletes may name the revision they expect, which turns a lost
  update into a conflict.
- **The whole configuration lives in memory** as an immutable snapshot. A change copies it,
  applies itself and validates the whole result, including references (a deleted list may not
  leave a group pointing at it). It then writes the changed rows and the audit entries in one
  transaction, before swapping the new snapshot in. Writes are serialized and block on disk I/O,
  so async callers run them on a blocking thread. Reads never touch the disk.
- **The data plane never reads the store.** The control plane compiles a resolver `Policy` from
  the snapshot and swaps it in (see `goethite::control`). Compiling the filter is the expensive
  step, so it only reruns when lists or rules change; other changes recompile the policy around
  the current filter.
- **Groups pick lists through filter sources** ([ADR 0004](0004-filter-engine.md)): custom rules
  are source 0 and every enabled list gets its own source. That limits a node to 63 lists.

## Consequences

- Restarting with a changed `[filter]` no longer changes filtering by itself. This is a
  deliberate break from Phase 1 behaviour, and the warning says what to do.
- A single file is easy to back up, and in Phase 3 it is what gets replicated.
- 63 lists per node is a real limit. Raising it means wider source masks in the filter.
- `goethite check-config` checks the TOML file, not the store.
