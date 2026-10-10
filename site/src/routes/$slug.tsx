import { createFileRoute, Link, notFound } from '@tanstack/react-router'
import { useEffect, useState, type MouseEvent } from 'react'

import { Header } from '../components/Header'
import { useInternalLinks } from '../components/links'
import { editUrl, type Heading, loadDoc, neighbours, sidebar } from '../docs'
import { pageHead } from '../head'

export const Route = createFileRoute('/$slug')({
	loader: async ({ params }) => {
		const doc = await loadDoc(params.slug)
		if (doc === undefined) {
			throw notFound()
		}
		return doc
	},
	head: ({ loaderData, params }) =>
		loaderData === undefined
			? {}
			: pageHead({
					title: loaderData.title,
					...(loaderData.description === undefined ? {} : { description: loaderData.description }),
					path: `/${params.slug}/`,
				}),
	component: DocPage,
})

function DocPage() {
	const doc = Route.useLoaderData()
	const { slug } = Route.useParams()
	const [menu, setMenu] = useState(false)
	useEffect(() => setMenu(false), [slug])
	// The changelog has a heading for every kind of change in every release; its versions are enough.
	const headings = slug === 'changelog' ? doc.headings.filter((heading) => heading.depth === 2) : doc.headings
	const { previous, next } = neighbours(slug)

	return (
		<div className="page">
			<Header
				menu={
					<button
						type="button"
						className="button menu-button needs-js"
						aria-expanded={menu}
						aria-controls="sidebar"
						onClick={() => setMenu(!menu)}
					>
						Menu
					</button>
				}
			/>
			<div className="docs">
				<nav id="sidebar" className="sidebar" data-open={menu} aria-label="Documentation">
					<ul>
						{sidebar.map((page) => (
							<li key={page.slug}>
								<Link to="/$slug/" params={{ slug: page.slug }}>
									{page.label}
								</Link>
							</li>
						))}
					</ul>
				</nav>
				<main id="content" className="main">
					<article data-pagefind-body>
						<h1>{doc.title}</h1>
						{headings.length > 0 ? (
							<details className="toc-inline" data-pagefind-ignore>
								<summary>On this page</summary>
								<Contents headings={headings} />
							</details>
						) : null}
						<Prose html={doc.html} />
					</article>
					<footer className="page-footer">
						<a href={editUrl(slug)}>Edit page</a>
						<nav className="pager" aria-label="Previous and next page">
							{previous === undefined ? null : (
								<Link to="/$slug/" params={{ slug: previous.slug }} rel="prev">
									<span className="muted">Previous</span>
									{previous.label}
								</Link>
							)}
							{next === undefined ? null : (
								<Link to="/$slug/" params={{ slug: next.slug }} rel="next" className="next">
									<span className="muted">Next</span>
									{next.label}
								</Link>
							)}
						</nav>
					</footer>
				</main>
				{headings.length > 0 ? (
					<nav className="toc" aria-labelledby="toc-title">
						<h2 id="toc-title">On this page</h2>
						<Contents headings={headings} />
					</nav>
				) : null}
			</div>
		</div>
	)
}

function Contents({ headings }: { headings: Heading[] }) {
	return (
		<ul>
			{headings.map((heading) => (
				<li key={heading.id} className={heading.depth === 3 ? 'sub' : undefined}>
					<a href={`#${heading.id}`}>{heading.text}</a>
				</li>
			))}
		</ul>
	)
}

/** The compiled Markdown, with working copy buttons and router links. */
function Prose({ html }: { html: string }) {
	const onLinkClick = useInternalLinks()

	function onClick(event: MouseEvent<HTMLDivElement>) {
		const button = event.target instanceof Element ? event.target.closest('button.copy') : null
		const code = button?.parentElement?.querySelector('pre')
		if (button instanceof HTMLButtonElement && code) {
			void navigator.clipboard.writeText(code.innerText).then(() => {
				button.textContent = 'Copied'
				setTimeout(() => (button.textContent = 'Copy'), 2000)
			})
			return
		}
		onLinkClick(event)
	}

	// The HTML is compiled at build time from this repository's Markdown (plugins/markdown.ts).
	return <div className="prose" onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />
}
