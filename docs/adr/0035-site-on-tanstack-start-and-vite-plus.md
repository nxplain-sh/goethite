# ADR 0035: Build the website with TanStack Start, and both web projects with Vite+

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

goethite has two web projects. `web/` is the admin UI, a TanStack Router single-page app embedded
in the binary under a strict Content Security Policy
([ADR 0002](0002-tanstack-router-spa-embedded.md)). `site/` is the public website and docs on
GitHub Pages, built with Astro Starlight: a second framework (Astro components, Starlight's content
collections and theme variables) next to the React and TanStack code of `web/`, with its own
toolchain.

`web/` had Vite, Vitest and `tsc`, and no linter or formatter. The maintainer wants one stack for
both: TanStack for the site, and [Vite+](https://viteplus.dev) (VoidZero's toolchain: Vite,
Vitest, Oxlint, Oxfmt and type-aware lint through tsgolint, behind one `vp` command) for both.

The website must stay static (GitHub Pages serves files only), readable without JavaScript and by
search engines, at the same URLs, with the same neobrutalist look, self-hosted fonts and no CDN.

## Decision

**The site is a TanStack Start app, prerendered.** Every page is rendered at build time into
`dist/client/<page>/index.html`, and the 404 page into `404.html`; GitHub Pages serves those
files. In the browser the same app takes over and moves between pages without reloading them.
The Markdown pages stay Markdown: a Vite plugin (`site/plugins/markdown.ts`) compiles each one at
build time with unified (remark, GitHub-flavoured Markdown) and Shiki into HTML plus its headings,
so no parser or highlighter is shipped. The sidebar, contents, prev/next and edit links, theme
menu, copy buttons and API reference page (Scalar's bundled build, as before) are plain React and
CSS. Search is Pagefind, as in Starlight, indexing the built pages, behind our own dialog.

**`web/` stays a Router SPA.** Start's prerendered pages carry inline scripts, which the UI's CSP
forbids, and the UI needs no server rendering (ADR 0002 holds).

**Both projects build with Vite+.** Each has `vite-plus` as a pinned devDependency, with `vite`
aliased to `npm:@voidzero-dev/vite-plus-core` in `devDependencies` and `overrides`, as
`vp migrate` writes it for npm. They stay on npm and their lockfiles, so CI, the reproducible
release build and Renovate keep working as they did: CI installs with `setup-node` and `npm ci`
and runs `vp` through the npm scripts. Vite+'s global installer and its `setup-vp` action are not
used. `npm run check` (`vp check`) formats with Oxfmt in the code's existing style (tabs, single
quotes, no semicolons), lints with Oxlint including type-aware rules, and type-checks; it replaces
`tsc --noEmit`. CI runs it for `web/` in the CI workflow, and for `site/` in the Site workflow on
pull requests, since CI skips pull requests that only change the site.

## Alternatives considered

- **Keep Astro Starlight.** It works, but it is a second framework and toolchain that only the
  site uses, and the maintainer asked for TanStack.
- **The site as a Router SPA, like `web/`.** One `index.html` rendered in the browser: no page
  content without JavaScript or for crawlers, and deep links on GitHub Pages only through a
  404.html redirect trick.
- **content-collections for the Markdown.** TanStack's guide suggests it, but it adds a build
  dependency and a config format for what a 200-line Vite plugin does with packages the site
  already had through Starlight.
- **Vite+'s global `vp` and the `setup-vp` action.** The global CLI also manages Node.js and the
  package manager, and installs with `curl | bash`. A pinned npm package keeps the toolchain in
  the lockfile, where `npm ci`, the release container and Renovate already handle it.
- **The lint plugin `vp migrate` adds** (`vite-plus/oxlint-plugin`, which asks for `vite-plus`
  imports). It runs on Oxlint's JavaScript plugin support, whose allocator panicked on Linux in a
  3.6 GB VM before linting anything; one cosmetic rule is not worth a lint that small machines
  cannot run.
- **Vite+'s default format** (double quotes, semicolons). It would have rewritten nearly every
  line of `web/` for no gain; the configured style changes about 500.

## Consequences

- One stack: React, TanStack and Vite+ across both projects, one lint and format setup, and the
  site's pages as React components that can share the UI's patterns.
- The site gains a lint and a type-check, and `web/` a linter and formatter. The type-check now
  covers `web/e2e/`, which `tsc` never checked.
- Starlight's features are ours to maintain: sidebar, contents, theme menu, search dialog, 404
  page and the Markdown plugin: about 1,200 lines of TypeScript and 840 of CSS.
- The site's lockfile shrinks (562 to 533 packages) and its build-time dependencies (unified,
  remark, Shiki, Pagefind, yaml, github-slugger) become direct ones; all were in it through
  Starlight. `web/` gains `vite-plus` and the Vitest browser packages it depends on, all
  development-only: the built UI is within 300 bytes of what plain Vite made (625 KB of
  JavaScript).
- Vite+ is young (1.x in 2026) and pins its own Vite, Vitest, Oxlint and Oxfmt versions, so those
  move together when `vite-plus` does; Renovate groups the alias with it. If Vite+ falls behind
  Vite or stops being maintained, `vite` and `vitest` go back to being direct dependencies, and
  the lint and format settings move to `.oxlintrc.json` and `.oxfmtrc.json`.
- `npm sbom --omit=dev` drops packages that runtime and development dependencies share, and the
  Vitest browser packages share three with Scalar; the release SBOM gap this widens is in the
  [backlog](../BACKLOG.md).
