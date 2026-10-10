import { createRouter } from '@tanstack/react-router'

import { routeTree } from './routeTree.gen'
import { basepath } from './site'

export function getRouter() {
	return createRouter({
		routeTree,
		basepath,
		// Every page is a directory with an index.html on GitHub Pages.
		trailingSlash: 'always',
		scrollRestoration: true,
		defaultPreload: 'intent',
	})
}

declare module '@tanstack/react-router' {
	interface Register {
		router: ReturnType<typeof getRouter>
	}
}
