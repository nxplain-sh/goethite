import { useEffect, useRef, useState } from 'react'

import { site } from '../site'
import { useInternalLinks } from './links'

// Pagefind indexes the built pages (`pagefind --site dist/client` in the
// build script) and serves its index next to them. Its script is loaded on the
// first search, from the site itself.

interface Result {
	url: string
	excerpt: string
	meta: { title?: string }
	sub_results: { title: string; url: string; excerpt: string }[]
}

interface Pagefind {
	options(options: { baseUrl: string }): Promise<void>
	init(): Promise<void>
	debouncedSearch(
		term: string,
		options?: object,
		ms?: number,
	): Promise<{ results: { id: string; data(): Promise<Result> }[] } | null>
}

type State =
	| { status: 'idle' }
	| { status: 'unavailable' }
	| { status: 'done'; term: string; results: Result[] }

async function load(): Promise<Pagefind | null> {
	try {
		const pagefind = (await import(/* @vite-ignore */ `${site.base}pagefind/pagefind.js`)) as Pagefind
		await pagefind.options({ baseUrl: site.base })
		await pagefind.init()
		return pagefind
	} catch {
		return null
	}
}

function typing(target: EventTarget | null): boolean {
	return (
		target instanceof HTMLElement &&
		(target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))
	)
}

export function Search() {
	const dialog = useRef<HTMLDialogElement>(null)
	const pagefind = useRef<Promise<Pagefind | null> | null>(null)
	const latest = useRef(0)
	const [term, setTerm] = useState('')
	const [state, setState] = useState<State>({ status: 'idle' })
	const onResultClick = useInternalLinks(() => dialog.current?.close())

	function open() {
		dialog.current?.showModal()
		pagefind.current ??= load()
	}

	useEffect(() => {
		function onKey(event: KeyboardEvent) {
			const shortcut =
				(event.key === 'k' && (event.metaKey || event.ctrlKey)) ||
				(event.key === '/' && !typing(event.target))
			if (shortcut && dialog.current?.open !== true) {
				event.preventDefault()
				open()
			}
		}
		window.addEventListener('keydown', onKey)
		return () => window.removeEventListener('keydown', onKey)
	}, [])

	async function search(next: string) {
		setTerm(next)
		const ticket = ++latest.current
		const engine = await (pagefind.current ??= load())
		if (engine === null) {
			setState({ status: 'unavailable' })
			return
		}
		if (next.trim() === '') {
			setState({ status: 'idle' })
			return
		}
		const found = await engine.debouncedSearch(next, {}, 150)
		if (found === null) {
			return
		}
		const results = await Promise.all(found.results.slice(0, 8).map((result) => result.data()))
		if (ticket === latest.current) {
			setState({ status: 'done', term: next, results })
		}
	}

	return (
		<>
			<button type="button" className="search-button needs-js" onClick={open}>
				Search <kbd>/</kbd>
			</button>
			<dialog
				ref={dialog}
				className="search"
				aria-label="Search the docs"
				// A click on the backdrop lands on the dialog itself and closes it.
				onClick={(event) => event.target === dialog.current && dialog.current.close()}
			>
				<div className="search-panel" onClick={onResultClick}>
					<div className="search-bar">
						<label className="sr-only" htmlFor="search-term">
							Search the docs
						</label>
						<input
							id="search-term"
							type="search"
							placeholder="Search the docs"
							autoComplete="off"
							value={term}
							onChange={(event) => void search(event.target.value)}
						/>
						<button type="button" className="button" onClick={() => dialog.current?.close()}>
							Close
						</button>
					</div>
					<Results state={state} />
				</div>
			</dialog>
		</>
	)
}

function Results({ state }: { state: State }) {
	if (state.status === 'unavailable') {
		return (
			<p className="muted">
				{import.meta.env.DEV
					? 'Search works in the built site: npm run build, then npm run preview.'
					: 'Search could not load. Try reloading the page.'}
			</p>
		)
	}
	if (state.status === 'idle') {
		return null
	}
	if (state.results.length === 0) {
		return <p className="muted">Nothing found for “{state.term}”.</p>
	}
	return (
		<ul className="search-results" aria-live="polite">
			{state.results.map((result) => (
				<li key={result.url}>
					<a href={result.url} className="search-title">
						{result.meta.title ?? result.url}
					</a>
					{/* Pagefind's excerpts are HTML: text from our own pages, with <mark> around the matches. */}
					<p dangerouslySetInnerHTML={{ __html: result.excerpt }} />
					{result.sub_results.length > 1 ? (
						<ul>
							{result.sub_results.slice(0, 3).map((sub) => (
								<li key={sub.url}>
									<a href={sub.url}>{sub.title}</a>
								</li>
							))}
						</ul>
					) : null}
				</li>
			))}
		</ul>
	)
}
