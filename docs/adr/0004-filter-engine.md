# ADR 0004: One FST over reversed labels, with a Bloom prefilter

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

goethite must hold a million or more filter rules in a small, bounded amount of memory and check
every query against them without slowing the hot path ([`AGENTS.md`](../../AGENTS.md#performance-rules)).
Rules match a name exactly, a name and everything below it (`||ads.example^`), or only the names
below it (`*.ads.example`), and exceptions (`@@`) override blocks. Lists are untrusted input
(B3 in the [threat model](../THREAT_MODEL.md)) and are rebuilt while queries keep flowing.

## Decision

- Every rule becomes one key in a single [`fst`](https://crates.io/crates/fst) map: the name's
  labels from the root down (`com`, `example`, `ads`), each lowercased and prefixed with its
  length. Length prefixes keep label boundaries unambiguous whatever bytes a label holds, and
  ordering from the root lets keys share their TLD and registered-domain prefixes.
- The value is a set of flags: block or allow, crossed with exact, subtree or subdomains-only.
  Rules for the same name share one key.
- A lookup walks the FST once along the queried name's key. At each label boundary where a key
  ends, subtree flags apply; exact flags apply only at the end of the name, subdomains-only flags
  only before it. One walk checks every suffix of the name.
- A Bloom filter over each rule's top two labels (or its only label) is checked first. It uses a
  fast, randomly seeded hash: a collision only costs one walk.
- Exceptions win over blocks. `reference_check` defines the semantics rule by rule; a property
  test and the `parse_list` fuzz target require the compiled filter to agree with it.
- A compiled `Filter` is immutable. The resolver holds it in an `ArcSwap`; reloads compile a new
  one off the async runtime and swap it in atomically.

## Consequences

Measured with `cargo bench -p goethite-filter --bench filter` (see [`bench/`](../../bench/README.md)):

- a million rules take 6.2 MiB, of which 1.25 MiB is the Bloom filter;
- lookups take 62 to 157 ns; the Bloom prefilter halves near misses (133 to 68 ns) and costs about
  11 ns on blocked names, which must walk the whole FST anyway;
- compiling is about 100 ms per 100,000 rules, so reloads stay under a few seconds.

Regular expressions cannot be compiled into an FST. They are unsupported for now and would need a
separate, size-bounded matcher run after the FST. Building needs all keys in memory at once to
sort them, a transient peak of a few tens of MiB for a million rules.

## Alternatives considered

- **A `HashSet` per scope, checking every suffix:** simple, but about 60 bytes or more per rule
  and one hash per label of every query.
- **Reversed bytes instead of reversed labels:** shares prefixes too, but blurs label boundaries,
  so `badexample.com` and `example.com` would need extra checks.
- **A trie of labels in memory (e.g. `HashMap` per node):** easy to update in place, but several
  times the memory, and in-place updates would need locking on the hot path.
- **No Bloom filter:** one fewer structure, but measurably slower on the most common case, misses.
