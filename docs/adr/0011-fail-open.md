# ADR 0011: When filtering fails, keep resolving (unless told not to)

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

goethite sits in front of every DNS query on a network. If it stops answering, the network stops
working. Filtering is a layer on top of resolution, and the architecture principles ask for a
fail-open option: if filtering fails, keep resolving rather than take the network down.

Until Phase 3, goethite already failed open in some places, and not in others:

- A list that cannot be read is skipped. A filter that fails to compile at runtime leaves the
  previous one in place. A failed first compile leaves the node unfiltered, but says so only in
  the log.
- A store file that cannot be opened stops goethite from starting at all. A corrupt control-plane
  database thus took DNS down, against the principle that losing the control plane never breaks
  resolution.
- The filter check runs on every query. goethite's code is linted against panics, but the check
  runs through third-party code (the FST). A panic there loses that query: tokio contains it to
  the query's task, and the client retries and fails again.

Some deployments want the opposite: in a school or under parental controls, unfiltered answers
are worse than none.

## Decision

`[filter] on_failure` is `"open"` (the default) or `"closed"`. It is a node setting in the
config file, deliberately not in the store, since it governs what happens when the store fails.

| Failure | open | closed |
| --- | --- | --- |
| The store file cannot be opened (corrupt, unreadable) | Run on a store in memory, seeded from the config file's `[filter]`; the file is left untouched | Refuse to start |
| The store is locked by another goethite | Refuse to start: that one is answering already | Refuse to start |
| The filter cannot be built at startup | Start unfiltered | Refuse to start |
| The filter cannot be rebuilt later | Keep the previous filter | Keep the previous filter |
| Checking a name fails (a panic) | Answer that query unfiltered | Answer SERVFAIL |

Every failure is reported, not just logged:

- `problems` in `GET /api/v1/status` explains each one in words.
- The TUI and the web UI show them.
- `goethite_degraded` is 1 while problems exist.
- `goethite_filter_failures_total` counts failed checks.

Failed checks are logged at the 1st, 2nd, 4th and 8th failure and so on, so a filter failing on
every query cannot flood the log.

The check is guarded with `catch_unwind` around one pure function call. That costs nothing
measurable when nothing panics, and it needs the default `panic = "unwind"`, which goethite
builds with.

## Consequences

- A node with a broken store keeps filtering as its config file says. Changes made through the
  API meanwhile live in memory and are lost on restart, and the status says so.
- A bug in the filter becomes visible (problems, metric, log) instead of silent lost answers.
- In closed mode, a corrupt store or broken filter means an outage until fixed, by choice.
- In closed mode, the store fallback is skipped entirely, not just made unfiltered.

## Alternatives considered

- **Restart on failure (systemd `Restart=`).** It does not help with a corrupt store or a filter
  that fails the same way every time. Restarts remain the answer to crashes.
- **Rebuilding a corrupt store from its file.** It risks the operator's data. goethite leaves the
  file alone and says what is wrong; recovery is a person's decision.
- **Catching panics for the whole query.** tokio already contains a panic to the query's task.
  The filter is where a failure has an obvious safe fallback (no filtering); elsewhere there is
  none better than a retry.
