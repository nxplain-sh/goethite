import { Link } from '@tanstack/react-router'

import { Header } from './Header'

/** The 404 page: prerendered as 404.html, and shown for unknown pages while browsing. */
export function NotFound() {
	return (
		<div className="page">
			<Header />
			<main id="content" className="not-found">
				<h1>Page not found</h1>
				<p>
					This page does not exist (yet). goethite is pre-alpha, so the docs are still growing. Try the
					search, or head back to the start.
				</p>
				<p className="actions">
					<Link to="/" className="button primary">
						Start
					</Link>
					<Link to="/$slug/" params={{ slug: 'quick-start' }} className="button">
						Quick start
					</Link>
				</p>
			</main>
		</div>
	)
}
