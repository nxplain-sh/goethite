# Contributing to goethite

Thanks for your interest. goethite is pre-alpha. Read [`AGENTS.md`](AGENTS.md) first: it
defines the architecture, security rules, conventions and roadmap, and it binds humans and coding
agents alike.

## Prerequisites

- [rustup](https://rustup.rs). The pinned toolchain (Rust 1.99.0 with rustfmt and clippy) installs
  automatically from `rust-toolchain.toml`. The MSRV is `rust-version = "1.99"` (edition 2024).
- Nightly Rust, only for fuzzing: `rustup toolchain install nightly`
- Supply-chain tools: `cargo install --locked cargo-deny cargo-audit`
- Fuzzing: `cargo install --locked cargo-fuzz`
- `dig` (from bind-utils / dnsutils) for manual checks
- Node.js 22.19 or newer, only if you work on the web UI in `web/` or the website in `site/`
  (CI uses Node 24)

## Build, test, lint

```sh
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Supply chain (licenses, advisories, banned crates, sources), for the main workspace and the
separate fuzz workspace:

```sh
cargo deny check
cargo audit
cargo deny --manifest-path fuzz/Cargo.toml check
cargo audit --file fuzz/Cargo.lock
```

Benchmarks (criterion; see [`bench/README.md`](bench/README.md) for recording results and the
dnsperf script):

```sh
cargo bench -p goethite-resolver --bench cache
cargo bench -p goethite-filter --bench filter
```

Run the server and query it:

```sh
cargo run -- run --config config/goethite.example.toml
dig @127.0.0.1 -p 15353 goethite.test        # -> 127.0.0.53
dig @127.0.0.1 -p 15353 example.com          # -> forwarded upstream
dig @127.0.0.1 -p 15353 goethite.test +tcp
```

Logs go to stderr and are controlled by `RUST_LOG` (default `info`; malformed packets are logged at
`debug`).

Chaos tests (Linux, root): a two-node cluster with a floating IP in network namespaces, broken
in several ways under load. See [`tests/chaos/README.md`](tests/chaos/README.md), also for
running them from macOS in a container.

```sh
cargo build --release
sudo tests/chaos/chaos.sh target/release/goethite
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, the tests on linux amd64
(`ubuntu-24.04`) and arm64 (`ubuntu-24.04-arm`), an MSRV check, `cargo deny` and `cargo audit`.
The fuzz and chaos workflows run weekly and on demand. All actions are pinned to commit SHAs. Keep
it that way when you edit workflows.

## Fuzzing

Every parser gets a fuzz target. Targets live in `fuzz/fuzz_targets/` and use
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer, nightly only).

| Target         | What it does                                                                                 |
| -------------- | -------------------------------------------------------------------------------------------- |
| `decode_query` | Decodes bytes via `goethite-proto`. On success, re-encodes, decodes again and asserts the two results are equal, including the case of the name, and that the name displays as printable ASCII. Every response goethite would send must fit in 512 bytes. |
| `decode_query_record` | Decodes bytes as a query log record read back from the store. On success, the record must encode and decode back to itself. |
| `decode_response` | Decodes bytes as an upstream response. On success, re-encodes and decodes again; the two results must be equal, since forwarding relies on that. |
| `parse_cidr`   | Parses text as a client network. On success, the network's display must parse back to the same network, which contains its own address. |
| `parse_list`   | Parses and compiles text as a filter list. For every parsed rule's name, its parent and a child, the compiled filter must agree with the rule-by-rule reference. |
| `parse_name`   | Parses text as a domain name. On success, the name's display must parse back to the same name. |
| `request_checks` | Runs the API's `Host`, `Origin` and web UI path checks on text. A `Host` taken for loopback must name this machine with at most a numeric port; an accepted path must not leave the UI's folder. |

Seeds are committed in `fuzz/seeds/<target>/`, and `crates/goethite-proto/tests/fuzz-seeds.rs`
checks that each one still behaves the way its name says. The working corpus (`fuzz/corpus/`) and
crash artifacts (`fuzz/artifacts/`) are gitignored, so create the corpus directory first.

Run a target for 60 seconds, writing new inputs to the working corpus and reading the seeds:

```sh
mkdir -p fuzz/corpus/decode_query
cargo +nightly fuzz run decode_query fuzz/corpus/decode_query fuzz/seeds/decode_query -- -max_total_time=60
```

Use the same commands with `parse_name` for the other target.

Reproduce and minimize a crash:

```sh
cargo +nightly fuzz run decode_query fuzz/artifacts/decode_query/<crash-file>
cargo +nightly fuzz tmin decode_query fuzz/artifacts/decode_query/<crash-file>
```

Every fixed crash gets a regression unit test in `goethite-proto` with the minimized input.

CI runs each target weekly (and on manual dispatch) for 5 minutes and uploads any crash artifacts,
kept for 7 days. The repository is public, so a crash found by CI is public from that moment: while
goethite is pre-alpha with no releases we accept that. Before the first release, fuzzing moves to
a private setup (see [`docs/BACKLOG.md`](docs/BACKLOG.md)). If you find a crash locally, report it
privately as described in [`SECURITY.md`](SECURITY.md).

### Adding a fuzz target

1. `cargo +nightly fuzz add <name>` from the repo root, or copy an existing target in
   `fuzz/fuzz_targets/`.
2. Fuzz the public parsing entry point, not internals. Where possible, check a property (such as
   decode, encode, decode round-tripping), not just "does not crash".
3. Add a few small, valid seed inputs under `fuzz/seeds/<name>/`.
4. Add the target to the weekly fuzz workflow and to the table above.

## Changing the API

The OpenAPI document `crates/goethite-api/openapi.json` is generated from the code and committed.
After changing the API, regenerate it and commit the result:

```sh
GOETHITE_UPDATE_OPENAPI=1 cargo test -p goethite-api --test openapi
```

Then regenerate the web UI's typed client and fix whatever the type-check reports:

```sh
cd web && npm run api && npm run check
```

CI fails if the committed document or client does not match the code. It also compares the document with
the base branch's, using [oasdiff](https://github.com/oasdiff/oasdiff), and fails on breaking
changes to `/api/v1`, such as a removed endpoint or field, or a new required field. If a breaking
change is intended (before 1.0 that is possible, and it goes in the changelog), add the
`api-breaking` label to the pull request.

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

## Web UI

The web UI lives in `web/` (Vite, React, TypeScript strict, TanStack Router/Query/Table/Virtual);
see [`web/README.md`](web/README.md). `npm run build` type-checks, builds to `web/dist` and checks
the size budget. Release builds of goethite embed `web/dist`; debug builds read it from disk.

```sh
cd web
npm ci --ignore-scripts
npm run build      # or `npm run dev` against a node on 127.0.0.1:8053
npm test           # Vitest: the forms' logic
npx playwright install chromium
npm run e2e        # Playwright: Chromium against a real goethite
```

`npm run build` also builds the API reference (`web/dist-docs`), which goethite serves at
`/api/docs` when `[api] docs` is on. The end-to-end tests start goethite themselves
(`web/e2e/serve.mjs`), from the workspace's debug build unless `GOETHITE_BIN` names another;
build goethite after `npm run build`, since release builds embed the files.

The page runs under a strict CSP: no inline scripts or styles, no `eval`, nothing from CDNs.

## Website

The project site lives in `site/` (Astro Starlight) and deploys to GitHub Pages from `main` via
`.github/workflows/pages.yml`. Deployment needs Pages enabled with source "GitHub Actions" (see
[Repository settings](#repository-settings-maintainers)).

```sh
cd site
npm ci --ignore-scripts
npm run dev
```

## Repository settings (maintainers)

Two one-time settings on `nxplain-sh/goethite` that the repository cannot set itself:

- **GitHub Pages:** Settings → Pages → Build and deployment → Source: **GitHub Actions**
  (or `gh api -X POST repos/nxplain-sh/goethite/pages -f build_type=workflow`). Without it the
  deploy job in `pages.yml` fails.
- **Private vulnerability reporting:** Settings → Code security → Private vulnerability
  reporting → Enable (or `gh api -X PUT repos/nxplain-sh/goethite/private-vulnerability-reporting`).
  [`SECURITY.md`](SECURITY.md) relies on it.

## Pull request checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo deny check` passes. Any new dependency is justified in the PR description.
- [ ] Web UI changes: `npm run build` in `web/` passes (type-check, build, size budget)
- [ ] Parser changes: the fuzz target was run for at least 60 seconds without findings
- [ ] No new `unwrap`/`expect`/panicking indexing on untrusted data
- [ ] Public items are documented. User-facing changes update `site/` or the README.
- [ ] Architectural decisions have an ADR. Later-phase ideas are in `docs/BACKLOG.md`.
- [ ] Commits follow the conventions above
