// Compiles each imported `.md` file to a module that exports the page as data
// ({ title, description, html, headings }; see src/markdown.d.ts). It runs at
// build time only, so no Markdown parser or highlighter reaches the browser.
//
// - Front matter (YAML) gives the title and description. Without a title, the
//   page's leading `# Heading` is the title and is taken out of the body.
// - Headings get GitHub-style ids (github-slugger), so links such as
//   `../groups/#blocked-services` keep working, and a "#" link beside them.
// - Code blocks are highlighted by Shiki in a light and a dark theme, picked
//   for at least 4.5:1 contrast on the site's code background in each.
// - Files outside the site (CHANGELOG.md) link to other repository files with
//   relative links; those are pointed at GitHub.
// - Raw HTML (such as <kbd>) passes through: the pages come from this repository.

import { dirname, relative, resolve } from 'node:path'

import GithubSlugger from 'github-slugger'
import rehypeStringify from 'rehype-stringify'
import remarkGfm from 'remark-gfm'
import remarkParse from 'remark-parse'
import remarkRehype from 'remark-rehype'
import { createHighlighter, type BundledLanguage } from 'shiki'
import { unified } from 'unified'
import type { Plugin } from 'vite-plus'
import { parse as parseYaml } from 'yaml'

const themes = { light: 'github-light-high-contrast', dark: 'github-dark-high-contrast' } as const

/** The parts of a hast node this plugin reads and writes. */
interface Node {
	type: string
	tagName?: string
	value?: string
	properties?: Record<string, unknown>
	children?: Node[]
}

interface Options {
	/** The repository root, for links in files outside the site. */
	repository: string
	/** Where GitHub shows repository files, ending in a slash. */
	blob: string
}

export function markdown({ repository, blob }: Options): Plugin {
	let site = ''
	const highlighter = createHighlighter({ themes: Object.values(themes), langs: [] })
	const parser = unified().use(remarkParse).use(remarkGfm).use(remarkRehype, { allowDangerousHtml: true })
	const printer = unified().use(rehypeStringify, { allowDangerousHtml: true })

	return {
		name: 'goethite:markdown',
		configResolved(config) {
			site = config.root
		},
		async transform(source, id) {
			if (!id.endsWith('.md')) {
				return null
			}
			const { data, body } = frontMatter(source, id)
			const tree = (await parser.run(parser.parse(body))) as Node
			const children = tree.children ?? []

			let title = typeof data.title === 'string' ? data.title : undefined
			const first = children.find((node) => node.type === 'element')
			if (title === undefined && first?.tagName === 'h1') {
				title = text(first)
				children.splice(children.indexOf(first), 1)
			}
			if (title === undefined) {
				throw new Error(`${id}: no title in the front matter and no leading # heading`)
			}

			const outside = relative(site, id).startsWith('..')
			const headings: { depth: number; id: string; text: string }[] = []
			const slugger = new GithubSlugger()
			const shiki = await highlighter

			await visit(tree, async (node, parent, index) => {
				if (node.tagName === undefined) {
					return
				}
				if (/^h[2-6]$/.test(node.tagName)) {
					const label = text(node)
					const slug = slugger.slug(label)
					node.properties = { ...node.properties, id: slug }
					const depth = Number(node.tagName.slice(1))
					if (depth <= 3) {
						headings.push({ depth, id: slug, text: label })
					}
					parent[index] = headingWithAnchor(node, slug, label)
				} else if (node.tagName === 'pre') {
					parent[index] = await codeBlock(node, shiki, id)
				} else if (node.tagName === 'table') {
					// Wide tables scroll inside the page instead of widening it.
					parent[index] = element('div', { className: ['table'] }, [node])
				} else if (node.tagName === 'a' && outside) {
					const href = node.properties?.href
					if (typeof href === 'string' && !/^([a-z]+:|#|\/)/i.test(href)) {
						const file = relative(repository, resolve(dirname(id), href))
						node.properties = { ...node.properties, href: `${blob}${file}` }
					}
				}
			})

			const html = printer.stringify(tree as never)
			const page = {
				title,
				...(typeof data.description === 'string' ? { description: data.description } : {}),
				html,
				headings,
			}
			return { code: `export default ${JSON.stringify(page)}`, map: null }
		},
	}
}

function frontMatter(source: string, id: string): { data: Record<string, unknown>; body: string } {
	const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(source)
	if (match === null) {
		return { data: {}, body: source }
	}
	const data: unknown = parseYaml(match[1] ?? '')
	if (typeof data !== 'object' || data === null) {
		throw new Error(`${id}: the front matter is not a YAML mapping`)
	}
	return { data: data as Record<string, unknown>, body: source.slice(match[0].length) }
}

/** Calls `action` on every node below `tree`, with the array that holds it. */
async function visit(
	tree: Node,
	action: (node: Node, parent: Node[], index: number) => Promise<void> | void,
): Promise<void> {
	const children = tree.children ?? []
	for (let index = 0; index < children.length; index++) {
		const node = children[index]
		if (node === undefined) {
			continue
		}
		await action(node, children, index)
		// A replaced node (a wrapper) is not visited again; the original is.
		await visit(node, action)
	}
}

function text(node: Node): string {
	if (node.type === 'text') {
		return node.value ?? ''
	}
	return (node.children ?? []).map(text).join('')
}

function element(tagName: string, properties: Record<string, unknown>, children: Node[]): Node {
	return { type: 'element', tagName, properties, children }
}

/**
 * The heading, followed by a link to it. The link sits beside the heading,
 * not inside it, so the heading's accessible name stays its own text.
 */
function headingWithAnchor(heading: Node, slug: string, label: string): Node {
	return element('div', { className: ['heading'] }, [
		heading,
		element('a', { className: ['anchor'], href: `#${slug}`, dataPagefindIgnore: '' }, [
			element('span', { ariaHidden: 'true' }, [{ type: 'text', value: '#' }]),
			element('span', { className: ['sr-only'] }, [{ type: 'text', value: `Section titled “${label}”` }]),
		]),
	])
}

type Highlighter = Awaited<ReturnType<typeof createHighlighter>>

/** A highlighted code block with a copy button (shown only with JavaScript). */
async function codeBlock(pre: Node, shiki: Highlighter, id: string): Promise<Node> {
	const code = pre.children?.find((node) => node.tagName === 'code')
	if (code === undefined) {
		return pre
	}
	const classes = code.properties?.className
	const language = Array.isArray(classes)
		? classes
				.map(String)
				.find((name) => name.startsWith('language-'))
				?.slice('language-'.length)
		: undefined
	const lang = language === undefined || language === 'text' ? 'text' : language
	if (lang !== 'text' && !shiki.getLoadedLanguages().includes(lang)) {
		try {
			await shiki.loadLanguage(lang as BundledLanguage)
		} catch {
			throw new Error(`${id}: Shiki has no language \`${lang}\``)
		}
	}
	const highlighted = shiki.codeToHast(text(code).replace(/\n$/, ''), {
		lang,
		themes,
		defaultColor: false,
	}) as Node
	const block = highlighted.children?.find((node) => node.tagName === 'pre') ?? pre
	return element('div', { className: ['code'] }, [
		block,
		element('button', { type: 'button', className: ['copy'], dataPagefindIgnore: '' }, [
			{ type: 'text', value: 'Copy' },
		]),
	])
}
