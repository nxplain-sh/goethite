# goethite website

The project website and docs: a [TanStack Start](https://tanstack.com/start) app built with
[Vite+](https://viteplus.dev) and prerendered to static HTML, one file per page, deployed to GitHub
Pages (`https://nxplain-sh.github.io/goethite/`) by `.github/workflows/pages.yaml`. That workflow
checks and builds the site on pull requests that change it, and deploys it on every push to `main`
that touches `site/**`, `CHANGELOG.md` or the OpenAPI document. The repository needs Pages enabled
once, with Settings → Pages → Source set to **GitHub Actions**; otherwise the deploy job fails.
Node.js 22.19 or newer is required (CI uses Node 24). See
[ADR 0035](../docs/adr/0035-site-on-tanstack-start-and-vite-plus.md) for why it is built this way.

```sh
cd site
npm ci --ignore-scripts   # install exact versions from package-lock.json
npm run dev               # http://localhost:4321/goethite/
npm run check             # vp check: Oxfmt, Oxlint, type-check; `npm run fmt` fixes the format
npm run build             # prerender every page into dist/client/, then index them for search
npm run preview           # serve dist/client/ the way GitHub Pages does, search included
```

## How it fits together

- **Pages** are Markdown files in `src/content/docs/`, with a `title` and a `description` in
  their front matter. A new file is a new page at `/<file name>/`; add it to the sidebar in
  `src/docs.ts`. Link between pages with relative links (`../filtering/#lists`), so a future custom
  domain, which drops the `/goethite` base, does not break them. The changelog page is the
  repository's `CHANGELOG.md`.
- **`plugins/markdown.ts`** compiles each Markdown file at build time into the page's HTML, its
  headings and its title: GitHub-style heading ids, Shiki highlighting in a light and a dark
  theme, and copy buttons. No Markdown parser or highlighter reaches the browser.
- **Routes** are in `src/routes/`: the landing page (`index.tsx`), every Markdown page
  (`$slug.tsx`), the API reference (`reference.tsx`, Scalar's bundled build reading
  `crates/goethite-api/openapi.json`) and the 404 page, which becomes `404.html`. The router
  plugin writes `src/routeTree.gen.ts`; commit it, CI checks that it is current.
- **Search** is [Pagefind](https://pagefind.app): `npm run build` indexes the prerendered pages
  into `dist/client/pagefind/`, and the search dialog loads that index on first use. The dev server
  has no index, so search works in `npm run preview`.
- **The theme** is `src/styles/site.css`: the neobrutalist palette from `AGENTS.md`, light and
  dark (the system's choice unless the theme menu overrides it). Every text/background pair must
  stay at or above 4.5:1 contrast in both.
- **Fonts** (Space Grotesk, JetBrains Mono) are bundled from npm and served from the site itself.
  Do not add font or script CDNs.
- `.npmrc` disables dependency install scripts (`ignore-scripts=true`). `vite` is aliased to
  Vite+'s core (`npm:@voidzero-dev/vite-plus-core`) in `devDependencies` and `overrides`; bump it
  together with `vite-plus`.
