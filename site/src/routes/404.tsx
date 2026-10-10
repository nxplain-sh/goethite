import { createFileRoute } from '@tanstack/react-router'

import { NotFound } from '../components/NotFound'
import { pageHead } from '../head'

// Prerendered to 404.html (vite.config.ts), which GitHub Pages serves for any missing path.
export const Route = createFileRoute('/404')({
	head: () => {
		const head = pageHead({ title: 'Page not found', path: '/404/' })
		return { ...head, meta: [...head.meta, { name: 'robots', content: 'noindex' }] }
	},
	component: NotFound,
})
