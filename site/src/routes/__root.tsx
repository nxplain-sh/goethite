import { createRootRoute, HeadContent, Scripts } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { NotFound } from '../components/NotFound'
import { site } from '../site'
import css from '../styles/site.css?url'

// Runs before the first paint: applies a theme picked earlier, so a dark page
// does not flash light, and marks that JavaScript runs, which shows the
// controls that need it (search, theme, copy buttons).
const boot = `(() => {
	const root = document.documentElement
	root.classList.add('js')
	try {
		const theme = localStorage.getItem('goethite-theme')
		if (theme === 'light' || theme === 'dark') root.dataset.theme = theme
	} catch {}
})()`

export const Route = createRootRoute({
	head: () => ({
		meta: [{ charSet: 'utf-8' }, { name: 'viewport', content: 'width=device-width, initial-scale=1' }],
		links: [
			{ rel: 'stylesheet', href: css },
			{ rel: 'icon', href: `${site.base}favicon.svg`, type: 'image/svg+xml' },
			{ rel: 'sitemap', href: `${site.base}sitemap.xml` },
		],
		scripts: [{ children: boot }],
	}),
	shellComponent: Shell,
	notFoundComponent: NotFound,
})

function Shell({ children }: { children: ReactNode }) {
	return (
		// The boot script sets a class and the theme on <html> before React hydrates.
		<html lang="en" suppressHydrationWarning>
			<head>
				<HeadContent />
			</head>
			<body>
				{children}
				<Scripts />
			</body>
		</html>
	)
}
