import { readdirSync } from 'node:fs'
import { join } from 'node:path'

import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import { defineConfig } from 'vite-plus'

import { markdown } from './plugins/markdown'
import { absolute, site } from './src/site'

const repository = join(import.meta.dirname, '..')

// Every page is prerendered to dist/client/<path>/index.html, which GitHub
// Pages serves as is. One route ($slug) serves all the Markdown pages, so they
// are listed here. Paths end in a slash, as the router's links do.
const docs = readdirSync(join(import.meta.dirname, 'src/content/docs'))
	.filter((file) => file.endsWith('.md') && !file.startsWith('.'))
	.map((file) => `/${file.slice(0, -'.md'.length)}/`)

export default defineConfig({
	base: site.base,
	// `vp check`: Oxfmt in the web UI's style, Oxlint with type-aware rules,
	// and a type-check.
	fmt: {
		singleQuote: true,
		semi: false,
		printWidth: 110,
		tabWidth: 2,
		ignorePatterns: ['src/routeTree.gen.ts', 'src/content/**'],
		// JSON and HTML keep the two spaces that npm and .editorconfig use.
		overrides: [{ files: ['*.{ts,tsx,mjs,css}'], options: { useTabs: true } }],
	},
	lint: {
		ignorePatterns: ['src/routeTree.gen.ts'],
		options: { typeAware: true, typeCheck: true },
	},
	oxc: { jsx: { runtime: 'automatic' } },
	plugins: [
		markdown({ repository, blob: `${site.repository}/blob/main/` }),
		tanstackStart({
			prerender: {
				enabled: true,
				autoStaticPathsDiscovery: false,
				crawlLinks: false,
				failOnError: true,
			},
			pages: [
				...['/', ...docs, '/changelog/', '/reference/'].map((path) => ({ path })),
				// GitHub Pages answers every missing path with this page.
				{ path: '/404/', prerender: { enabled: true, outputPath: '/404.html' }, sitemap: { exclude: true } },
			],
			sitemap: { enabled: true, host: absolute('') },
		}),
	],
	server: {
		port: 4321,
		strictPort: true,
		// The changelog and the API reference come from outside the site.
		fs: { allow: ['.', '../CHANGELOG.md', '../crates/goethite-api/openapi.json'] },
	},
})
