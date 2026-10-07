# Kickoff prompt — paste this into Claude Code

> Put `AGENTS.md` in the root of an empty `goethite` repo first, then start Claude Code there and paste everything below the line.

---

You are starting the **goethite** project from an empty repository. Read [`AGENTS.md`](AGENTS.md) in full first — it defines the vision, architecture, security rules, conventions and roadmap. Treat it as binding.

Your task is **Phase 0 — Foundation**. Do not start Phase 1 work.

## Before you write any code

1. Summarize your understanding of goethite and Phase 0 in a few sentences.
2. Ask me for these decisions if they are not already filled in below, and wait for my answers:
   - License: **[MIT / Apache-2.0 / dual MIT+Apache-2.0 / AGPL-3.0]**
   - GitHub org/repo path: **nxplain-sh/goethite** (decided)
   - MSRV: default to the current stable Rust release unless I say otherwise
3. Present a plan: the files you will create, in order, and anything you are unsure about. Wait for my approval.

## Phase 0 deliverables

**1. Cargo workspace**
- Root `Cargo.toml` as a virtual workspace with every crate from the layout in [`AGENTS.md`](AGENTS.md) (empty library skeletons are fine; each with a crate-level doc comment saying its purpose).
- Shared `[workspace.package]` (edition 2024, rust-version, license, repository) and `[workspace.dependencies]` for versions used across crates.
- `[workspace.lints]` that enforce the security rules: `unsafe_code = "forbid"` where required, clippy `unwrap_used`, `expect_used`, `indexing_slicing`, `panic` denied in non-test code of proto/filter/resolver; `-D warnings` in CI.
- `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`.

**2. Minimal working server**
- `goethite` binary with clap: `goethite run --config <path>` and `goethite --version`.
- Loads a minimal TOML config (`[server] listen = "127.0.0.1:5353"`), with a commented example at `config/goethite.example.toml`.
- Listens on UDP and TCP, parses the incoming query via `goethite-proto` (wrapping hickory-proto behind our own small trait/types), and answers `A goethite.test.` with `127.0.0.53`; every other name gets `REFUSED`. Malformed packets are dropped without panicking and logged at debug.
- Structured logging with `tracing` + `tracing-subscriber` (env filter).
- Graceful shutdown on SIGINT/SIGTERM.

**3. Tests**
- Integration test that starts the server on an ephemeral port and checks the UDP and TCP answers, plus the REFUSED case.
- Property test (proptest) that encoding then decoding a query round-trips.
- A test that random/garbage bytes never cause a panic.

**4. Fuzzing**
- `fuzz/` with a cargo-fuzz target for query parsing through `goethite-proto`.
- Document how to run it in [`CONTRIBUTING.md`](CONTRIBUTING.md).

**5. CI (GitHub Actions)**

- Jobs: fmt check, clippy (`-D warnings`), tests on linux amd64 + arm64 (arm64 may be cross/QEMU or a native runner), MSRV check, `cargo-deny` (licenses, advisories, bans, sources), `cargo-audit`.
- A scheduled weekly job running the fuzz target for a few minutes.
- Cache cargo builds. Pin actions to commit SHAs.

**6. Documentation**

- [`README.md`](README.md): one-paragraph pitch, status ("pre-alpha, Phase 0"), dev quick start (`cargo run -- run --config config/goethite.example.toml` then `dig @127.0.0.1 -p 5353 goethite.test`).
- [`SECURITY.md`](SECURITY.md): how to report vulnerabilities privately; supported versions ("none yet").
- `docs/THREAT_MODEL.md`: first draft — assets (DNS availability, query privacy, config integrity, admin access), attackers (LAN clients, malicious upstreams, off-path spoofers, compromised filter lists, supply chain), what goethite defends against in which phase, and explicit non-goals.
- `docs/adr/0001-hickory-proto-behind-trait.md` and `docs/adr/0002-tanstack-router-spa-embedded.md` (Router SPA, not Start; why).
- `docs/BACKLOG.md` for anything you notice that belongs to later phases.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): build, test, fuzz, commit conventions.

**7. Website skeleton (GitHub Pages)**

- `site/` with Astro Starlight: a landing page (pitch + "pre-alpha" status), a Quick start page mirroring the README, and a placeholder "API reference" page saying it arrives in Phase 2.
- Apply the neobrutalist tokens from [`AGENTS.md`](AGENTS.md) (borders, hard shadows, palette, self-hosted Space Grotesk + JetBrains Mono). Keep it simple; polish comes later.
- A GitHub Actions workflow that builds `site/` and deploys to GitHub Pages on pushes to `main` (only when `site/**` changes). Pin actions to commit SHAs. Tell me which repo setting I need to enable for Pages.

**8. Repo hygiene**

- `.gitignore`, `deny.toml`, `LICENSE` (per my answer), `.editorconfig`.
- Do not create the `web/` app yet beyond an empty folder with a README placeholder.

## Exit criteria (check each before you finish)

- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace` all pass locally.
- `cargo deny check` passes.
- `dig @127.0.0.1 -p 5353 goethite.test` returns `127.0.0.53`; `dig ... example.com` returns REFUSED.
- The fuzz target builds and runs for at least 60 seconds without findings.
- No `unwrap`/`expect` on network-derived data anywhere.

## When you finish

Report: what you built, the exact commands to verify it, any deviations from [`AGENTS.md`](AGENTS.md) and why, open questions, and a proposed task breakdown for Phase 1 (do not start it). Commit in logical, conventional-commit chunks rather than one big commit.
