# ADR 0009: Serving the web UI, and keeping browsers from turning against the API

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

[ADR 0002](0002-tanstack-router-spa-embedded.md) chose a client-only single-page app embedded into
the binary. Phase 2 builds its skeleton, and that raises questions ADR 0002 left open: where the
UI is served, who may fetch its files, where the admin token lives in the browser, and how a
browser pointed at goethite stays safe.

The last point matters most. The API's no-token mode answers anyone on loopback. Before the UI
existed only local programs used it, but the UI puts a browser on the admin's machine, and that
browser also runs pages from any site. Two classic attacks follow:

- **DNS rebinding.** A hostile site sets its name to resolve to 127.0.0.1. Its page then reaches
  `http://evil.example:8053/api/v1/…` *as the same origin*, so it can read the query log and
  change filtering. CORS does not help: the browser sees no cross-origin request. (goethite's own
  rebinding protection only helps when the browser uses goethite as its resolver.)
- **Cross-site requests.** A page cannot read responses from another origin without CORS, but it
  can send some requests without a preflight check, for example a `POST` with no body, which is
  enough to trigger a list refresh.

## Decision

**One listener.** The API's listener serves the UI for every path no API route matches. There is
no second port, and HTTPS covers the UI too. `[api] web_ui = false` turns the UI off.

**Files are public; data is not.** The UI's files need no token: they hold no data, and everything
they show comes from the API, which still requires the token. A path that is not a file gets
`index.html`, so deep links work. `/api` and `/api/…` never get it (an unknown API path is a JSON
404), and neither do missing `/assets/…` files (a stale asset is a 404, not HTML). Lookups accept
only plain relative paths (ASCII letters, digits, `._-`, no `.` or `..` segments). Hashed assets are
cached for a year (`immutable`), `index.html` is revalidated (`no-cache`), and API answers stay
`no-store`.

**Embedded at build time, from `web/dist`.** rust-embed (with deterministic timestamps, for
reproducible builds later) embeds the directory in release builds and reads it from disk in debug
builds. A build without `web/dist` has no UI and says so in the log; Rust CI does not need Node.
A separate CI job builds the UI, embeds it in a release build and fetches it.

**Every request passes a browser guard** before authentication:

- Without an admin token, the `Host` (or HTTP/2 `:authority`) must name this machine:
  `localhost`, a name under `.localhost` (browsers resolve those to loopback themselves), a
  loopback address, and at most a numeric port. A rebinding page sends its own name, so it gets
  a 403. With a token, any name works: a rebinding page does not have the token.
- A request carrying an `Origin` must come from the API's own origin (scheme ignored, host and
  port compared case-insensitively). Browsers send `Origin` on every request that can change
  something. curl, the TUI and Terraform send none and are unaffected. `Origin: null` is refused.

**The token lives in `sessionStorage`.** Without a server session layer (ADR 0002), the UI sends
the token as a bearer header. `sessionStorage` survives a reload but not closing the tab, and other
origins cannot read it. A 401 clears it and returns to the sign-in page, and the page offers
sign-out. Cookies were rejected: they would bring back CSRF, which header tokens avoid.

**The page itself stays strict.** The existing CSP (`script-src 'self'`, `style-src 'self'`,
`font-src 'self'`, no `unsafe-inline`, `frame-ancestors 'none'`) applies to the UI unchanged.
The build inlines nothing (`assetsInlineLimit: 0`, no module-preload polyfill), fonts are
self-hosted from npm, and React's style properties go through the CSSOM, which `style-src` does
not restrict. A size budget (200 KiB of gzipped JavaScript) fails the build when exceeded.

## Consequences

- Anyone who can reach the API's port can download the UI's code. It is open source anyway.
- The `Host` check means a no-token node is reachable in a browser only as `localhost`,
  `127.0.0.1` or `[::1]` (an SSH tunnel works). Reaching it by another name needs a token, which
  is required beyond loopback anyway.
- A script injected into the UI could read the token from `sessionStorage`. The CSP is the defense:
  no inline code, no third-party origins. React escapes everything rendered, and the UI never sets
  raw HTML.
- The search-parameter validators must return every key they know (`undefined` when a value is
  invalid): TanStack Router merges their output over the raw parameters, so a key left out would
  keep its raw, unchecked value. Found while testing an open-redirect attempt on the sign-in page.
- The theme follows the system until the user picks one. Applying a stored choice before the
  first paint would need an inline script, which the CSP forbids, so it applies on start-up instead.

## Alternatives considered

- **A separate port for the UI.** One more listener, certificate and set of limits, for nothing:
  the UI needs the API's origin anyway to call it without CORS.
- **Authenticating the UI's files.** Browsers cannot attach a bearer token to the page load, so
  this would mean cookies and with them CSRF. The files are not secret.
- **CORS with an allow-list instead of the `Origin` check.** goethite needs no cross-origin
  access at all. Refusing foreign origins outright is simpler and stricter.
- **`localStorage` for the token.** It would survive closing the browser and be shared by every
  tab, which is more exposure for little convenience.
