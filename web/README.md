# web/

The goethite web UI: a single-page app built with [Vite+](https://viteplus.dev), React, TypeScript
(strict), TanStack Router, Query, Table, Virtual and Charts. It talks only to the REST API, through
a typed client generated from [`openapi.json`](../crates/goethite-api/openapi.json). The build in
`dist/` is embedded into the `goethite` binary and served next to the API with a strict Content
Security Policy. See
[ADR 0002](../docs/adr/0002-tanstack-router-spa-embedded.md),
[ADR 0009](../docs/adr/0009-web-ui-serving.md),
[ADR 0017](../docs/adr/0017-dashboard-charts.md) and
[ADR 0035](../docs/adr/0035-site-on-tanstack-start-and-vite-plus.md).

```sh
npm ci --ignore-scripts
npm run check   # vp check: Oxfmt, Oxlint, type-check; `npm run fmt` fixes the format
npm run build   # build to dist/, check the size budget, build dist-docs/
npm test        # Vitest: the forms' logic (src/forms)
npm run e2e     # Playwright: Chromium against a real goethite (e2e/), after
                # `npx playwright install chromium`
```

Build the UI before building goethite to include it. Release builds embed `dist/`; debug builds
read it from disk at run time, so after `npm run build` a running debug goethite serves the new
UI on reload. A goethite built without `dist/` simply has no web UI.

## Developing

```sh
cargo run -- run --config config/goethite.example.toml   # in the repository root
npm run dev                                              # http://localhost:5173
```

The dev server proxies `/api` to the node on `127.0.0.1:8053`.

## Testing

The pages' logic that needs no browser (turning forms into the specs goethite stores and back,
addresses, schedule windows) lives in `src/forms` and is tested with Vitest. Everything else is
tested end to end: `e2e/serve.mjs` starts goethite with a fresh store, a known token and the API
reference on, and the tests in `e2e/` sign in and use the UI as a person would, checking the
result through the API.

## The API reference

`npm run build` also gzips Scalar's standalone bundle into `dist-docs/`, which goethite embeds
and serves at `/api/docs` when `[api] docs` is on. It is kept out of `dist/` and its budget.

## When the API changes

`npm run api` regenerates `src/api/schema.d.ts` from `openapi.json`. CI fails when it is out of
date, and the type-check then shows every page the change affects.

## Rules

- No inline scripts or styles in HTML, no `eval`, no CDNs, no data: URLs: the page runs under
  `script-src 'self'; style-src 'self'; font-src 'self'`. Fonts are self-hosted from npm.
- Never rely on color alone: every state carries a text label.
- The design tokens live in [`src/styles/tokens.css`](src/styles/tokens.css); every text and
  background pair there is at least 4.5:1. There is one theme, light.
- `scripts/budget.mjs` caps the bundle (200 KiB of gzipped JavaScript). Raise it only on purpose.
- Test files import from `vite-plus/test`, not `vitest`, and config from `vite-plus`, not `vite`.
  `vite` is aliased to Vite+'s core
  (`npm:@voidzero-dev/vite-plus-core`) in `devDependencies` and `overrides`; bump it together with
  `vite-plus`.
