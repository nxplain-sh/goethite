import { useQueryClient } from '@tanstack/react-query'
import { useSyncExternalStore } from 'react'

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
 * Links to the documentation and the API reference, in the bottom right
 * corner of every page. The API reference is this node's own (this build's
 * API) when it serves one, which it does to loopback only, and the site's
 * otherwise.
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
				className="button small"
				href={DOCS_URL}
				target="_blank"
				rel="noopener noreferrer"
				title="goethite's documentation, in a new tab"
			>
				Docs<span aria-hidden="true"> ↗</span>
			</a>
			<a
				className="button small"
				href={apiDocs}
				target="_blank"
				rel="noopener noreferrer"
				title={
					local
						? "This node's API reference, in a new tab"
						: 'The API reference on the documentation site, in a new tab'
				}
			>
				API docs<span aria-hidden="true"> ↗</span>
			</a>
		</nav>
	)
}
