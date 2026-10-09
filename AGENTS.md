# goethite — project context for coding agents

goethite is a self-hosted, clustered, security-hardened DNS filtering resolver written in Rust. Goal: be better than Pi-hole, AdGuard Home, NextDNS (self-hosted alternative) and Numa on **security**, **performance** and **high availability** — while matching AdGuard Home on everyday filtering features. Named after the iron-oxide mineral that is a main component of rust.

Part of the [nxplain.sh](https://nxplain.sh) open source org. Repo: [`github.com/nxplain-sh/goethite`](https://github.com/nxplain-sh/goethite).

## Positioning and scope

In scope for 1.0:

- DNS filtering, caching, forwarding, encrypted DNS (DoH / DoT / DoQ / ODoH)
- Per-client groups, schedules, full AdGuard/uBlock DNS filter syntax, CNAME uncloaking, safe search
- Clustering with HA: replicated config, floating IP (VRRP), zero-downtime reload and upgrade
- Interfaces: REST API, TUI (`goethite tui`), embedded web UI, Terraform provider
- Project website + docs on GitHub Pages, with a Scalar API reference built from the OpenAPI spec
- Recursive resolution with full DNSSEC validation (later phase)

Out of scope for 1.0: hosted cloud service, developer features like Numa's `.numa` proxy/mDNS, Windows as a server platform. Linux (amd64 + arm64) is first-class; macOS is for development only.

## Architecture principles

- **Data plane vs control plane.** Every node answers DNS fully on its own. Losing the control plane (API, cluster sync, UI) must never break resolution.
- **Resolution pipeline (in order):** client identification → policy/group lookup → local rewrites → filter check (incl. CNAME uncloaking) → cache → upstream (forward or recursive) → DNSSEC validation → response.
- **Fail-open option:** if filtering fails, keep resolving rather than take the network down.
- **Hot paths never block:** compiled filter lists and config are swapped atomically (`arc-swap`).
- **One source of truth for config:** the replicated config store is authoritative. TOML is for bootstrap. Resources created via Terraform carry `managed_by = "terraform"` and are read-only in the UI and TUI.

## Workspace layout

```
crates/
  goethite-proto/     DNS wire format; wraps hickory-proto behind our own trait
  goethite-filter/    rule parsing (hosts, domain lists, AdGuard syntax) + FST/Bloom compiler
  goethite-resolver/  cache, forwarding, upstream pool, (later) recursion + DNSSEC
  goethite-server/    listeners: UDP/TCP 53, DoT, DoH, DoQ; SO_REUSEPORT, per-core sockets
  goethite-cluster/   config sync, VRRP, (later) Raft via openraft
  goethite-api/       axum REST API, /api/v1, OpenAPI via utoipa
  goethite-store/     embedded storage (redb) for query log, stats, config
  goethite-tui/       ratatui client that talks to the API
  goethite-migrate/   reads Pi-hole / AdGuard Home API answers and plans the same in goethite
  goethite/           the binary: CLI (clap), wiring, systemd integration
xtask/                repository automation: `cargo xtask ci` runs what CI runs
web/                  Vite + React + TanStack Router SPA (embedded into the binary)
site/                 project website + docs (Astro Starlight), deployed to GitHub Pages
fuzz/                 cargo-fuzz targets (own nightly workspace)
bench/                dnsperf script + recorded results; criterion benches live in crates/*/benches/
tests/chaos/          chaos lab: two nodes and a client in network namespaces
tests/packages/       installs the .deb and .rpm on each supported distribution
deploy/               hardened systemd units, server config, package and container image definitions
config/               example config
docs/                 architecture, threat model, ADRs
```

The layout follows the [standard Rust project layout](https://github.com/miguelmartens/standard-rust-project-layout); [ADR 0025](docs/adr/0025-standard-rust-project-layout.md) records where goethite deviates and why. Read it before adding a crate, a top-level directory or a workspace lint.

The Terraform provider lives in a separate repo (`terraform-provider-goethite`, Go, terraform-plugin-framework) and is built from the OpenAPI spec. Do not start it before Phase 3.5.

## Tech stack

- Rust stable, edition 2024, MSRV pinned in `rust-toolchain.toml` and `Cargo.toml`
- tokio (multi-thread), hickory-proto, axum, utoipa, rustls, arc-swap, fst, redb, serde + toml, tracing, clap, ratatui, thiserror (libraries) / anyhow (binary only)
- Web: Vite, React, TypeScript (strict), TanStack Router (SPA, NOT TanStack Start), TanStack Query, TanStack Table + Virtual; typed API client generated from the OpenAPI spec; served from the binary via rust-embed with an SPA fallback route

## Security rules (non-negotiable)

- `#![forbid(unsafe_code)]` in `goethite-proto`, `goethite-filter`, `goethite-resolver`. Any `unsafe` elsewhere needs a written justification and a `// SAFETY:` comment.
- **Never panic on network input.** No `unwrap`/`expect`/indexing that can panic on data from the wire, config, or API. Enforce with clippy (`unwrap_used`, `expect_used`, `indexing_slicing`) in non-test code of the crates above.
- Bound everything: message sizes, label counts, compression pointer loops, CNAME chain depth, cache size, connection counts, request timeouts.
- Resolver defenses: random source ports, 0x20 case randomization, response matching on ID + question, DNS rebinding protection, response rate limiting.
- Drop privileges after binding port 53; ship a hardened systemd unit (no new privileges, `CAP_NET_BIND_SERVICE` only, protected paths). Landlock/seccomp later.
- The API binds to loopback until an admin token is configured. All config changes are audit-logged.
- Every parser gets a fuzz target. New dependencies must pass `cargo-deny` and be justified in the PR description — prefer fewer, well-maintained crates.

## Performance rules

- No heap allocation in the per-query hot path where reasonably avoidable; reuse buffers.
- Never hold a lock across `.await`. Prefer sharded or lock-free structures for the cache.
- Every performance claim needs a criterion bench or a reproducible dnsperf run in `bench/`.
- Targets: sub-millisecond p99 for cached answers; 1M+ filter rules in a small, bounded memory footprint (FST + Bloom prefilter); no dropped queries during reload.

## Code conventions

- `cargo xtask ci` must pass: it runs every check CI runs.
- Modules with children use `foo.rs` beside `foo/`; only shared integration-test helpers live in `tests/<name>/mod.rs`. File names in `tests/`, `benches/` and `examples/` are kebab-case: they are target names.
- Errors: `thiserror` in libraries, `anyhow` only in the binary. Log with `tracing`, never `println!`.
- Public items get doc comments. Architectural decisions get a short ADR in `docs/adr/`.
- Tests: unit tests next to code, integration tests in `tests/`, property tests (proptest) for encode/decode round-trips.
- Conventional commits (`feat:`, `fix:`, `chore:` …). Small, focused changes.

## Website and API docs

- `site/` is an Astro Starlight site, deployed to GitHub Pages by a GitHub Actions workflow ([`nxplain-sh.github.io/goethite`](https://nxplain-sh.github.io/goethite/) unless a custom domain is set). Same neobrutalist look as the app; self-hosted fonts.
- Content: landing page, install + quick start, config reference, filter syntax, HA guide, Terraform guide, security (threat model, verifying signed releases), benchmarks, changelog.
- API reference: Scalar, rendered from `openapi.json`, which CI generates from the Rust code (utoipa) and commits as an artifact for the site. CI fails on breaking API changes to `/api/v1` (e.g. with oasdiff) unless the change is marked intentional.
- In the binary, `/api/docs` (Scalar) is OFF by default, loopback-only when enabled, and serves bundled assets — never a CDN — so the strict CSP still holds.
- Docs ship with features: a feature is not done until its docs page is updated.

## UI design: neobrutalism

Shared by the web UI and (where possible) the TUI.

- Thick borders (3px, ink color), hard offset shadows with no blur (`6px 6px 0 ink`), no gradients, little or no rounding, buttons that "press" (shadow shrinks, element shifts).
- Type: Space Grotesk (headings/UI), JetBrains Mono (domains, IPs, numbers). Self-host fonts — no CDNs at runtime.
- Palette (light): bg `#F2ECE1`, panel `#FFFDF8`, ink `#111111`, accent ochre `#E8A33D`, blocked rust `#A63D22`, ok teal `#1D6B5F`, cached `#F6DFA8`.
- The web UI has one theme, light. Palette (dark), for the website only: bg `#15120E`, panel `#211C16`, ink `#F2ECE1`, rust `#E06A4B`, teal `#5CC2B0`.
- Accessibility: 4.5:1 text contrast, visible focus states, never rely on color alone (blocked/allowed always carry a text label).

## Roadmap (respect the order)

- **Phase 0 — Foundation:** workspace, CI, security tooling, fuzz harness, threat model, site skeleton deployed to GitHub Pages, a server answering a hardcoded query.
- **Phase 1 — v0.1 core blocker:** listeners, forwarding (plain/DoH/DoT) with failover, sharded TTL cache, filter engine (hosts, domain lists, core AdGuard syntax) compiled to FST + Bloom with hot swap, scheduled list updates, hardened systemd unit.
- **Phase 2 — v0.2 control:** Scalar API reference on the site + breaking-change check, client groups + schedules, CNAME uncloaking, safe search, query log
  - stats, Prometheus metrics, `/api/v1` + OpenAPI, audit log, TUI, web app skeleton + design tokens.
- **Phase 3 — v0.3 HA:** two-node config sync over mTLS, VRRP floating IP, graceful reload via socket handoff, cluster-wide stats, fail-open, chaos tests.
- **Phase 3.5 — Terraform provider** (separate repo).
- **Phase 4 — v0.4:** full web UI, DoH/DoT/DoQ server, ODoH, recursion + DNSSEC.
- **Phase 5 — v0.5:** Raft clustering (openraft, with a vote-only witness), reproducible signed builds, SBOM, packaging (.deb, .rpm, container image), fuzzing out of public CI (local runs before each release), Landlock + seccomp sandboxing, client access control, local DNS records, importers from Pi-hole and AdGuard Home, external security review.
- **1.0:** not scheduled yet; it follows v0.5.

## How to work in this repo

- Plan before coding: for any non-trivial task, outline the approach and files to touch first.
- Branch from and target `development`; `main` takes pull requests from `development` only ([Branches](CONTRIBUTING.md#branches)).
- Stay inside the current phase. If something belongs to a later phase, note it in [`docs/BACKLOG.md`](docs/BACKLOG.md) instead of building it.
- Ask before adding a dependency, changing the public API, or changing anything in the security rules above.
- Before saying a task is done: `cargo xtask ci` and (for parser changes) a short fuzz run pass. Summarize what changed and what is left.
- Development binds to port `15353` by default so it runs without root; production uses `53`. (Not `5353`: that is the multicast DNS port, held by mDNSResponder on macOS and often by Avahi on Linux.)