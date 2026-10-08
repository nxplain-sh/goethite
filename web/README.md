# web/

The goethite web UI: a single-page app built with Vite, React, TypeScript (strict), TanStack
Router, Query, Table and Virtual. It talks only to the REST API, through a typed client generated
from [`openapi.json`](../crates/goethite-api/openapi.json). The build in `dist/` is embedded into
the `goethite` binary and served next to the API with a strict Content Security Policy. See
[ADR 0002](../docs/adr/0002-tanstack-router-spa-embedded.md) and
[ADR 0009](../docs/adr/0009-web-ui-serving.md).

```sh
npm ci --ignore-scripts
npm run build   # type-check, build to dist/, check the size budget
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

## When the API changes

`npm run api` regenerates `src/api/schema.d.ts` from `openapi.json`. CI fails when it is out of
date, and the type-check then shows every page the change affects.

## Rules

- No inline scripts or styles in HTML, no `eval`, no CDNs, no data: URLs: the page runs under
  `script-src 'self'; style-src 'self'; font-src 'self'`. Fonts are self-hosted from npm.
- Never rely on color alone: every state carries a text label.
- The design tokens live in [`src/styles/tokens.css`](src/styles/tokens.css); every text and
  background pair there is at least 4.5:1 in both themes.
- `scripts/budget.mjs` caps the bundle (200 KiB of gzipped JavaScript). Raise it only on purpose.
