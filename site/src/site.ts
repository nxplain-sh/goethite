// Where the site lives. It is a GitHub Pages project site, so every path sits
// under /goethite/. If a custom domain is set up later, change `origin` and
// set `base` to '/': the Markdown pages link to each other with relative
// links, so they need no change.
export const site = {
	origin: 'https://nxplain-sh.github.io',
	base: '/goethite/',
	title: 'goethite',
	description: 'A self-hosted, clustered, security-hardened DNS filtering resolver written in Rust.',
	repository: 'https://github.com/nxplain-sh/goethite',
	// Pull requests go to development (docs/branching.md), so edits start there.
	editBase: 'https://github.com/nxplain-sh/goethite/edit/development/',
}

/** The router's basepath: `base` without its trailing slash. */
export const basepath = site.base.replace(/\/$/, '')

/** The absolute URL of a path inside the site, such as `/quick-start/`. */
export function absolute(path: string): string {
	return `${site.origin}${basepath}${path}`
}
