import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { site } from '../site'
import { Search } from './Search'
import { ThemeSelect } from './ThemeSelect'

/** The bar on top of every page except the API reference. `menu` opens the sidebar on narrow screens. */
export function Header({ menu }: { menu?: ReactNode }) {
	return (
		<>
			<a className="skip-link" href="#content">
				Skip to content
			</a>
			<header className="header">
				{menu}
				<Link to="/" className="brand">
					<Logo />
					<span className="brand-name">{site.title}</span>
				</Link>
				<Search />
				<div className="header-end">
					<ThemeSelect />
					<a className="button" href={site.repository}>
						GitHub
					</a>
				</div>
			</header>
		</>
	)
}

/** The favicon's mark: a rust block with an ochre core and a hard shadow. */
function Logo() {
	return (
		<svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true">
			<rect x="7" y="7" width="23" height="23" fill="var(--ink)" />
			<rect x="2" y="2" width="23" height="23" fill="#a63d22" stroke="var(--ink)" strokeWidth="3" />
			<rect x="9" y="9" width="9" height="9" fill="#e8a33d" stroke="var(--ink)" strokeWidth="2" />
		</svg>
	)
}
