// The documentation pages: their order in the sidebar, and how each one is
// loaded. Every page except the changelog is a Markdown file in
// src/content/docs/, compiled to HTML at build time by plugins/markdown.ts.

import { site } from './site'

/** A heading on a page, for its table of contents. */
export interface Heading {
	depth: 2 | 3
	id: string
	text: string
}

/** A compiled Markdown page (see `*.md` in markdown.d.ts). */
export interface Doc {
	title: string
	description?: string
	html: string
	headings: Heading[]
}

/** The sidebar, in reading order. Prev/next links follow it too. */
export const sidebar = [
	{ label: 'Quick start', slug: 'quick-start' },
	{ label: 'Install on Linux', slug: 'install' },
	{ label: 'Verifying releases', slug: 'verify' },
	{ label: 'Moving from Pi-hole or AdGuard Home', slug: 'migrate' },
	{ label: 'Configuration', slug: 'configuration' },
	{ label: 'Filtering', slug: 'filtering' },
	{ label: 'Clients and groups', slug: 'groups' },
	{ label: 'Local records', slug: 'local-records' },
	{ label: 'DNS leak test', slug: 'leak-test' },
	{ label: 'Encrypted DNS', slug: 'encrypted-dns' },
	{ label: 'Recursion', slug: 'recursion' },
	{ label: 'High availability', slug: 'ha' },
	{ label: 'REST API', slug: 'api' },
	{ label: 'Metrics and telemetry', slug: 'observability' },
	{ label: 'Web UI', slug: 'web-ui' },
	{ label: 'Terminal UI', slug: 'tui' },
	{ label: 'Security settings', slug: 'security' },
	{ label: 'API reference', slug: 'api-reference' },
	{ label: 'Changelog', slug: 'changelog' },
] as const

const markdown = import.meta.glob<Doc>('./content/docs/*.md', { import: 'default' })

/** Loads a page, or returns undefined when there is no page by that name. */
export async function loadDoc(slug: string): Promise<Doc | undefined> {
	if (slug === 'changelog') {
		const { default: changelog } = await import('../../CHANGELOG.md')
		return { ...changelog, description: 'What changed in each goethite release.' }
	}
	return markdown[`./content/docs/${slug}.md`]?.()
}

/** The page before and after this one in the sidebar. */
export function neighbours(slug: string) {
	const index = sidebar.findIndex((page) => page.slug === slug)
	return {
		previous: index > 0 ? sidebar[index - 1] : undefined,
		next: index >= 0 ? sidebar[index + 1] : undefined,
	}
}

/** GitHub's editor for the file a page is written in. */
export function editUrl(slug: string): string {
	return `${site.editBase}${slug === 'changelog' ? 'CHANGELOG.md' : `site/src/content/docs/${slug}.md`}`
}
