# ADR 0002: Web UI as an embedded TanStack Router SPA, not TanStack Start

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

goethite gets a web admin UI starting in Phase 2 (skeleton and design tokens), with the full UI in
Phase 4. The UI must:

- ship inside the single `goethite` binary. Appliances must not need Node.js or any other runtime.
- talk only to the Rust REST API (`/api/v1`). That API is the single source of truth, and the TUI
  and Terraform provider use it too.
- work under a strict Content Security Policy, with no CDNs at runtime.
- serve authenticated admins on a LAN. It does not need SEO or public-facing first-paint
  performance.

The TanStack ecosystem fits our data-heavy screens (query log, stats, rule lists): TanStack Router
provides type-safe routing, TanStack Query handles data, and TanStack Table + Virtual render large
lists. TanStack offers two ways to build an app: **TanStack Router** (a client-side router) and
**TanStack Start** (a full-stack framework on top of Router with SSR, streaming and server
functions).

## Decision

The web UI is a client-only single-page app:

- Vite + React + TypeScript (strict) + TanStack Router, with TanStack Query, Table and Virtual.
- A typed API client generated from the OpenAPI spec that `goethite-api` produces with utoipa.
- Built to static assets in `web/`, embedded into the binary with `rust-embed`, and served by axum.
  An SPA fallback route returns `index.html` for non-asset, non-API paths so deep links work.

We do **not** use TanStack Start.

## Consequences

Positive:

- One self-contained binary. There is no Node.js on the appliance and no second server process.
- The Rust API stays the only backend. There are no server functions that could drift from the API
  that Terraform and the TUI use.
- Smaller attack surface and fewer moving parts. Static assets make a strict CSP with no inline
  scripts straightforward.
- UI assets are versioned with the binary, so UI and API always match.

Negative:

- Authentication is handled client-side against the API. Token storage, expiry and logout need
  care because there is no server-side session layer.
- No SSR, so the first load downloads the bundle. Bundle size matters: budget it and code-split
  routes.
- Deep links depend on the axum fallback route. It must not shadow `/api/*` or asset paths.
- The OpenAPI-generated client needs regenerating whenever the API changes. CI should check that it
  is up to date.

## Alternatives considered

- **TanStack Start.** It wants a JavaScript server runtime for SSR and server functions, which
  breaks the single-binary, no-Node requirement and adds a second backend next to the Rust API. SSR
  and SEO bring nothing to an authenticated admin UI. Rejected.
- **Pre-rendering Start to static output.** This loses most of what Start adds while keeping its
  complexity. Plain Router is simpler. Rejected.
- **Server-rendered HTML from axum (templates + htmx).** No JS build step, but data-heavy
  interactive screens (virtualized logs, live stats) are harder, and we would lose the typed client
  generated from OpenAPI. Rejected for now.
- **Other SPA stacks (React Router, SvelteKit SPA mode, Solid).** Viable, but TanStack Router's
  type-safe routes and search params combined with Query, Table and Virtual fit the planned screens
  best.
