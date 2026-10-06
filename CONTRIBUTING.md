# Contributing to goethite

Thanks for your interest. goethite is pre-alpha (Phase 0). Read [`AGENTS.md`](AGENTS.md) first: it
defines the architecture, security rules, conventions and roadmap, and it binds humans and coding
agents alike.

## Prerequisites

- [rustup](https://rustup.rs). The pinned toolchain (Rust 1.99.0 with rustfmt and clippy) installs
  automatically from `rust-toolchain.toml`. The MSRV is `rust-version = "1.99"` (edition 2024).
- Nightly Rust, only for fuzzing: `rustup toolchain install nightly`
- Supply-chain tools: `cargo install --locked cargo-deny cargo-audit`
- Fuzzing: `cargo install --locked cargo-fuzz`
- `dig` (from bind-utils / dnsutils) for manual checks
- Node.js 22.12 or newer, only if you work on the website in `site/`

## Build, test, lint

```sh
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Supply chain (licenses, advisories, banned crates, sources):

```sh
cargo deny check
cargo audit
```

Run the server and query it:

```sh
cargo run -- run --config config/goethite.example.toml
dig @127.0.0.1 -p 15353 goethite.test        # -> 127.0.0.53
dig @127.0.0.1 -p 15353 example.com          # -> REFUSED
dig @127.0.0.1 -p 15353 goethite.test +tcp
```

Logs go to stderr and are controlled by `RUST_LOG` (default `info`; malformed packets are logged at
`debug`).

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, the tests on linux amd64
(`ubuntu-24.04`) and arm64 (`ubuntu-24.04-arm`), an MSRV check, `cargo deny` and `cargo audit`. All
actions are pinned to commit SHAs. Keep it that way when you edit workflows.

## Fuzzing

Every parser gets a fuzz target. Targets live in `fuzz/fuzz_targets/` and use
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer, nightly only).

| Target         | What it does                                                                                 |
| -------------- | -------------------------------------------------------------------------------------------- |
| `decode_query` | Decodes bytes via `goethite-proto`. On success, re-encodes, decodes again and asserts the two results are equal, including the case of the name. Every response goethite would send must fit in 512 bytes. |

Seeds are committed in `fuzz/seeds/decode_query/`, and `crates/goethite-proto/tests/fuzz_seeds.rs`
checks that each one still decodes the way its name says. The working corpus (`fuzz/corpus/`) and
crash artifacts (`fuzz/artifacts/`) are gitignored.

Run for 60 seconds, writing new inputs to the working corpus and reading the seeds:

```sh
cargo +nightly fuzz run decode_query fuzz/corpus/decode_query fuzz/seeds/decode_query -- -max_total_time=60
```

Reproduce and minimize a crash:

```sh
cargo +nightly fuzz run decode_query fuzz/artifacts/decode_query/<crash-file>
cargo +nightly fuzz tmin decode_query fuzz/artifacts/decode_query/<crash-file>
```

Every fixed crash gets a regression unit test in `goethite-proto` with the minimized input.

CI runs each target weekly (and on manual dispatch) for 5 minutes and uploads any crash artifacts.

### Adding a fuzz target

1. `cargo +nightly fuzz add <name>` from the repo root, or copy an existing target in
   `fuzz/fuzz_targets/`.
2. Fuzz the public parsing entry point, not internals. Where possible, check a property (such as
   decode, encode, decode round-tripping), not just "does not crash".
3. Add a few small, valid seed inputs under `fuzz/seeds/<name>/`.
4. Add the target to the weekly fuzz workflow and to the table above.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <summary in imperative mood>
```

- Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `build`, `perf`.
- Scope: the crate name without the `goethite-` prefix (`proto`, `filter`, `resolver`, `server`,
  `cluster`, `api`, `store`, `tui`), `cli` for the binary, or an area like `site`, `fuzz`, `docs`.
- Examples: `feat(proto): reject queries with more than one question`,
  `ci: pin cargo-deny to 0.20`.
- Keep commits small and focused. One logical change per commit.

## Rules recap

The full list is in [`AGENTS.md`](AGENTS.md). The short version:

- **Never panic on network input.** No `unwrap`, `expect`, `panic!` or panicking indexing/slicing
  on data from the wire, config or API. Clippy denies `unwrap_used`, `expect_used`,
  `indexing_slicing`, `panic`, `string_slice` and `arithmetic_side_effects` (overflow panics in
  debug builds) workspace-wide in non-test code. `clippy.toml` allows the panic family inside
  `#[test]` functions and `#[cfg(test)]` modules. Helpers in integration tests (`tests/*.rs`) are
  not covered, so those files carry a crate-level `#![allow(...)]` with a reason.
- **No `unsafe`.** `unsafe_code = "forbid"` is set workspace-wide, and `goethite-proto`,
  `goethite-filter` and `goethite-resolver` also carry `#![forbid(unsafe_code)]`.
- **Bound everything:** message sizes, label counts, loops, chain depths, cache sizes, connection
  counts, timeouts.
- Errors: `thiserror` in libraries, `anyhow` only in the binary.
- Logging: `tracing`, never `println!`/`eprintln!`.
- Public items get doc comments. Clippy pedantic is on, so its warnings fail CI.
- Architectural decisions get a short ADR in [`docs/adr/`](docs/adr/).
- New dependencies must pass `cargo deny check` and be justified in the PR description. Prefer
  fewer, well-maintained crates.
- Stay inside the current phase. Work that belongs to a later phase goes in
  [`docs/BACKLOG.md`](docs/BACKLOG.md).
- Docs ship with features. A feature is not done until its docs page is updated.

## Website

The project site lives in `site/` (Astro Starlight) and deploys to GitHub Pages from `main` via
`.github/workflows/pages.yml`.

```sh
cd site
npm ci --ignore-scripts
npm run dev
```

## Pull request checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo deny check` passes. Any new dependency is justified in the PR description.
- [ ] Parser changes: the fuzz target was run for at least 60 seconds without findings
- [ ] No new `unwrap`/`expect`/panicking indexing on untrusted data
- [ ] Public items are documented. User-facing changes update `site/` or the README.
- [ ] Architectural decisions have an ADR. Later-phase ideas are in `docs/BACKLOG.md`.
- [ ] Commits follow the conventions above
