# goethite website

The project website and docs, built with [Astro Starlight](https://starlight.astro.build) and
deployed to GitHub Pages (`https://nxplain-sh.github.io/goethite/`) by
`.github/workflows/pages.yaml` on every push to `main` that touches `site/**`. The repository needs
Pages enabled once, with Settings → Pages → Source set to **GitHub Actions**; otherwise the deploy
job fails. Node.js 22.19 or newer is required (CI uses Node 24).

```sh
cd site
npm ci --ignore-scripts   # install exact versions from package-lock.json
npm run dev               # http://localhost:4321/goethite/
npm run build             # static output in site/dist/
```

- Pages live in `src/content/docs/`. Use relative links between pages so a future custom domain
  (which drops the `/goethite` base) does not break them.
- The neobrutalist theme is `src/styles/theme.css`. Every text/background pair must stay at or
  above 4.5:1 contrast in both light and dark mode.
- Fonts (Space Grotesk, JetBrains Mono) are bundled from npm and served from the site itself.
  Do not add font or script CDNs.
- `.npmrc` disables dependency install scripts (`ignore-scripts=true`). The `overrides` entry in
  `package.json` pins a patched `postcss-selector-parser` (GHSA-rj75-hqrm-r3gf) until
  expressive-code updates `postcss-nested`. Remove it once `npm ls postcss-selector-parser`
  shows 7.1.6 or newer without it.
