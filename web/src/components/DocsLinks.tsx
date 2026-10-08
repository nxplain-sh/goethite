import { useQueryClient } from '@tanstack/react-query'
import { type ReactNode, useSyncExternalStore } from 'react'

import { statusQuery } from '../api/queries'

/** The documentation site. */
export const DOCS_URL = 'https://nxplain-sh.github.io/goethite/'

/** The API reference on the documentation site. */
export const SITE_API_DOCS_URL = `${DOCS_URL}api-reference/`

/** Whether `hostname` is this machine, so the browser connects from loopback. */
export function isLoopback(hostname: string): boolean {
	return (
		hostname === 'localhost' ||
		hostname.endsWith('.localhost') ||
		/^127\.\d+\.\d+\.\d+$/.test(hostname) ||
		hostname === '[::1]'
	)
}

/**
 * Links to the documentation and the API reference, as a joined pair: in the
 * top bar of every page, and under the sign-in form. The API reference is
 * this node's own (this build's API) when it serves one, which it does to
 * loopback only, and the site's otherwise.
 */
export function DocsLinks() {
	// Read from what the pages fetch, never fetched for this: the sign-in
	// page has no token, and asking would only log an error. Watched in the
	// cache itself, which signing in and out clears.
	const queryClient = useQueryClient()
	const servesDocs = useSyncExternalStore(
		(changed) => queryClient.getQueryCache().subscribe(changed),
		() => queryClient.getQueryData(statusQuery.queryKey)?.api_docs === true,
	)
	const local = servesDocs && isLoopback(window.location.hostname)
	const apiDocs = local ? '/api/docs' : SITE_API_DOCS_URL
	return (
		<nav className="docs-links" aria-label="Documentation">
			<a
				href={DOCS_URL}
				target="_blank"
				rel="noopener noreferrer"
				aria-label="Docs"
				title="goethite's documentation, in a new tab"
			>
				<BookIcon />
				<span className="docs-label">Docs</span>
				<OutIcon />
			</a>
			<a
				href={apiDocs}
				target="_blank"
				rel="noopener noreferrer"
				aria-label="API docs"
				title={
					local
						? "This node's API reference, in a new tab"
						: 'The API reference on the documentation site, in a new tab'
				}
			>
				<BracesIcon />
				<span className="docs-label">API docs</span>
				<OutIcon />
			</a>
		</nav>
	)
}

// Icons drawn with straight strokes and square ends, to match the borders.

function Icon({ size, className, children }: { size: number; className?: string; children: ReactNode }) {
	return (
		<svg
			className={className}
			width={size}
			height={size}
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth="2.5"
			strokeLinecap="square"
			strokeLinejoin="miter"
			aria-hidden="true"
			focusable="false"
		>
			{children}
		</svg>
	)
}

/** An open book. */
function BookIcon() {
	return (
		<Icon size={18}>
			<path d="M12 6v14" />
			<path d="M12 6 3 4v14l9 2 9-2V4z" />
		</Icon>
	)
}

/** Curly braces, drawn angular. */
function BracesIcon() {
	return (
		<Icon size={18}>
			<path d="M8 3H6v7l-3 2 3 2v7h2" />
			<path d="M16 3h2v7l3 2-3 2v7h-2" />
		</Icon>
	)
}

/** Opens elsewhere: an arrow out of the corner. */
function OutIcon() {
	return (
		<Icon size={12} className="docs-out">
			<path d="M7 17 17 7" />
			<path d="M9 7h8v8" />
		</Icon>
	)
}
