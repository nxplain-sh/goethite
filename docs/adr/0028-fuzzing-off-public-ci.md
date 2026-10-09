# ADR 0028: Fuzz locally before each release, not in public CI

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

Every goethite parser has a cargo-fuzz target. Until v0.4 a weekly workflow ran each of them for
five minutes in this public repository and uploaded crash inputs as artifacts for seven days.
For goethite a crash is almost always a packet, list or message that makes a parser panic or
stall, so the crashing input is a ready-made attack on every running node. While nobody ran
goethite from a release, `SECURITY.md` accepted that trade-off; v0.5 ships packages and a
container image, so a finding published by CI would be a public attack before its fix. Hiding the
artifacts is not enough: the failing run, its log and its stack trace already say which parser
breaks, and often how.

The alternatives each cost something: a private mirror repository that fuzzes on a schedule
(another repository and its settings to keep), or OSS-Fuzz (which usually wants a sizeable user
base first).

## Decision

**Fuzzing runs on maintainers' machines, as a step of every release; public CI only builds the
fuzz targets.**

- `cargo xtask fuzz [--seconds N] [target ...]` runs every target (or those named) one after
  another, 300 seconds each by default, on the nightly that `fuzz/rust-toolchain.toml` pins. The
  corpus in `fuzz/corpus/` (gitignored) grows from run to run, seeded from `fuzz/seeds/`. A
  crash ends its own target and is named at the end, with its input in `fuzz/artifacts/`.
- The release steps in `CONTRIBUTING.md` include a full run before tagging, and findings are
  fixed privately first, as `SECURITY.md` describes.
- `.github/workflows/fuzz.yaml` builds every target with the pinned nightly on changes to the
  parsers, so the targets keep compiling; it never runs them.
- The nightly is dated, so a run builds the targets the same way until it is bumped on purpose.

## Alternatives considered

- **A private repository fuzzing on a schedule:** continuous coverage, but another repository,
  its Actions minutes and its secrets to look after; worth it once goethite has users who would
  feel a regression between releases.
- **OSS-Fuzz:** continuous and private, but acceptance usually needs a sizeable user base.
- **Public CI without artifacts:** the failing job still discloses the parser and the stack.

## Consequences

- Between releases, nothing fuzzes unless someone runs `cargo xtask fuzz`; the parsers' unit and
  property tests and the seed checks still run on every change, and the AGENTS.md rule stays: a
  parser change gets a short fuzz run before it is done.
- A full run takes about 90 minutes for 17 targets; it needs a machine that does not sleep, since
  libFuzzer's time limit is wall-clock.
- Revisit when goethite has users: then a private scheduled setup (or OSS-Fuzz) is worth its cost.
