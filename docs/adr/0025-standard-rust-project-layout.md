# ADR 0025: Follow the standard Rust project layout, with recorded deviations

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

goethite reached v0.4.0 with a layout that grew phase by phase. The
[standard Rust project layout](https://github.com/miguelmartens/standard-rust-project-layout)
separates what Cargo defines (target discovery, `src/`, `tests/`, `benches/`, naming) from
recommendations for what Cargo leaves open (workspace shape, lints, tooling, directories). An audit
against it found most of it already in place: a virtual manifest with resolver 3, flat `crates/`,
inherited package metadata and `[lints] workspace = true` everywhere, a committed `Cargo.lock` with
`--locked` CI, the MSRV declared once, `thiserror` in libraries and `anyhow` in the binary, and
`lib.rs` façades of private modules and `pub use`.

The gaps: two `mod.rs` modules among `foo.rs` ones, snake_case integration test and fuzz targets
(Cargo 1.100 warns about the latter: `cargo::non_kebab_case_bins`), internal dependencies without
a `version`, no `.gitattributes`, no rustdoc or shellcheck in CI (rustdoc turned out to have three
broken links), no single command for the CI checks, deployment files in `dist/` beside the
`web/dist` and `site/dist` build output, no `unreachable_pub` or `missing_debug_implementations`
lints, no release profile, and no `.env` ignore rule.

## Decision

goethite follows the layout. The gaps above are closed: `foo.rs` + `foo/` modules, kebab-case test
and fuzz targets (seed directories included), `path` + `version` internal dependencies and an
explicit members list, `.gitattributes` (LF, fuzz seeds byte-exact), rustdoc and shellcheck jobs,
`cargo xtask ci` (no dependencies), the systemd units in `deploy/`, both lints, thin LTO with one
codegen unit ([measured](../../bench/README.md#release-profile)), `.env` ignored and `.env.example`
listing every variable goethite reads, and Renovate grouping routine updates weekly with lockfile
maintenance and a three-day minimum release age.

Where goethite deviates, it does so on purpose:

1. **`unsafe_code` is `deny` in the workspace and `forbid` in crate roots**, not a workspace
   `forbid`. The binary and goethite-cluster each need one justified `unsafe` block. `forbid`
   cannot be lifted by `#[allow]`, and Cargo has no per-crate override of one workspace lint, so
   those crates would have to copy the whole lint table. Every other crate, xtask included, carries
   `#![forbid(unsafe_code)]`, which the security rules in `AGENTS.md` require.
2. **The panic family is `deny`, not `warn`**: never panic on network input. `clippy.toml` allows
   it in `#[test]` functions and `#[cfg(test)]` modules; integration test crates, which it does not
   cover, carry one `#![allow]` with a reason.
3. **The toolchain is pinned to an exact release equal to the MSRV** (`channel = "1.99.0"`), not
   `stable`. Reproducible, later signed, builds need the exact compiler; `cargo xtask toolchain`
   and the MSRV job keep the two in step. goethite is an application, so its MSRV is the pinned
   release rather than one trailing stable.
4. **The fuzz workspace names its goethite dependencies by path only.** It is a nightly-only
   workspace of its own, never published, and cannot inherit from the main workspace.
5. **Error enums are not `#[non_exhaustive]`.** The crates are internal (`publish = false`); a
   sibling crate's exhaustive match should break when a variant is added.
6. **Some library modules stay `pub`** (`goethite_proto::dnssec`, `goethite_resolver::recurse`,
   `goethite_server::{doh, doq, odoh}`, `goethite_cluster::vrrp`, ...), where the namespace is part
   of the API on purpose.
7. **No Prettier, pre-commit or Makefile.** Prettier in CI means an npm download outside a
   lockfile and a second style beside `web/` and `site/`; `.editorconfig` and `.gitattributes`
   cover line endings and indentation. `cargo xtask ci` is the one entry point.
8. **CI calls cargo directly**, a job per check, so a failure names itself; xtask mirrors the jobs
   locally and both change together.
9. **Top-level directories with no Rust convention:** `web/`, `site/`, `fuzz/`, `bench/` (dnsperf
   and recorded results; criterion benches are in each crate's `benches/`), `config/`, and
   `tests/chaos/`, a shell-driven lab rather than a Cargo target (the root manifest is virtual, so
   Cargo never reads a root `tests/`).
10. **The release profile keeps unwinding and symbols**, unlike `panic = "abort"` and
    `strip = "symbols"` templates: a panicking task fails alone instead of taking the listeners
    down, and journal backtraces name their functions.

## Alternatives considered

- **Workspace `unsafe_code = "forbid"`, with the full lint table copied into the two crates that
  need `unsafe`:** two copies of twenty lints drift; the crate-root `forbid` gives the same
  guarantee for the other crates.
- **xtask as a separate, excluded workspace:** keeps `cargo build --workspace` from building it,
  at the cost of a second lockfile and lint table. `default-members` already keeps a bare
  `cargo run` on goethite.
- **Keeping `dist/`:** the standard layout accepts any name chosen once, but `dist/` reads like the
  gitignored build output next to it.
- **Keeping snake_case fuzz targets** (`decode_query`), as cargo-fuzz's scaffolding names them:
  Cargo now warns about every one, and the fuzz workflow runs the nightly that does. ADRs before
  this one keep the old names, as written.

## Consequences

- A release bumps `workspace.package.version` and the internal crates' `version` in
  `[workspace.dependencies]` together.
- Release builds take about a quarter longer and the binary is about a quarter smaller; lookups
  move by a few nanoseconds either way.
- New public types need a `Debug` that prints nothing secret and nothing large, and items other
  crates cannot reach are `pub(crate)`; the lints say so in review.
- If Cargo gains per-crate overrides of single workspace lints, revisit deviation 1. If Prettier or
  dprint can run pinned from a lockfile in CI, revisit 7.
