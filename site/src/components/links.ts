import { useRouter } from '@tanstack/react-router'
import type { MouseEvent } from 'react'

import { site } from '../site'

/**
 * A click handler for HTML the router did not render (compiled Markdown,
 * search results): links to other pages of the site go through the router,
 * like its own links, instead of loading the page again. Anything else (other
 * sites, new tabs, links within the page) is left to the browser.
 */
export function useInternalLinks(after?: () => void) {
	const router = useRouter()
	return (event: MouseEvent<HTMLElement>) => {
		if (!(event.target instanceof Element)) {
			return
		}
		const link = event.target.closest('a')
		if (
			link === null ||
			event.defaultPrevented ||
			event.button !== 0 ||
			event.metaKey ||
			event.ctrlKey ||
			event.shiftKey ||
			event.altKey ||
			link.target !== '' ||
			link.hasAttribute('download')
		) {
			return
		}
		const url = new URL(link.href)
		if (url.origin !== window.location.origin || !url.pathname.startsWith(site.base)) {
			return
		}
		after?.()
		if (url.pathname === window.location.pathname && url.hash !== '') {
			return
		}
		event.preventDefault()
		void router.navigate({ href: `${url.pathname}${url.search}${url.hash}` })
	}
}
