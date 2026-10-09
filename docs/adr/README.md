# Architecture decision records

One short record per decision that is expensive to reverse, or that someone will predictably ask
about: a dependency, a protocol choice, a crate boundary, a deliberate deviation from a convention
goethite otherwise follows. Not for reversible, local choices.

## Conventions

- One file per decision, `NNNN-kebab-case-title.md`, numbered in order and never renumbered.
  `0000` is the [template](0000-template.md), not a decision.
- Title the decision as a decision: "Wrap hickory-proto behind our own trait and types", not
  "DNS parsing".
- Status is `Proposed`, `Accepted`, `Superseded by ADR NNNN` or `Deprecated`. An ADR that adds to
  an earlier one says so in both status lines ("extends ADR 0018" / "extended by ADR 0022").
- **Records are not rewritten.** A changed decision gets a new ADR; the old one only gets its
  status line updated to point at it. Editing history to look consistent destroys the one thing
  the directory is for: what was known, and what lost, at the time.
- Keep it to about a page. Longer material goes in [`../`](../) and the ADR links to it.

## Writing one

```sh
cp docs/adr/0000-template.md docs/adr/0026-short-title.md
```

Sections, in this order: **Context** (what forced a decision), **Decision** (what we do),
**Alternatives considered** (what else was on the table and why it lost), **Consequences** (what it
costs, and what would make us revisit it). Records before ADR 0025 put Alternatives last or leave
it out; they stay as written.

The Alternatives section is the reason to write an ADR at all: "we chose X" can be read off the
code, "we tried Y and it could not do Z" cannot.
