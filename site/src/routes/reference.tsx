import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef } from 'react'

import { pageHead } from '../head'
import specUrl from '../../../crates/goethite-api/openapi.json?url'
// The package exports no path to its standalone build, so it is read where npm installs it.
import scalarUrl from '../../node_modules/@scalar/api-reference/dist/browser/standalone.js?url'

// The API reference: Scalar, rendered in the browser from the OpenAPI
// document that CI keeps in step with the Rust code. Everything is bundled
// and served from this site: no CDN, no remote fonts, no telemetry, and no
// "try it" client (goethite's API is not reachable from here anyway).
const configuration = {
	url: specUrl,
	theme: 'none',
	layout: 'modern',
	withDefaultFonts: false,
	telemetry: false,
	hideClientButton: true,
	hideTestRequestButton: true,
	showDeveloperTools: 'never',
	mcp: { disabled: true },
	agent: { disabled: true },
	documentDownloadType: 'json',
	customCss: `
		.light-mode, .dark-mode {
			--scalar-font: 'Space Grotesk Variable', system-ui, sans-serif;
			--scalar-font-code: 'JetBrains Mono Variable', ui-monospace, monospace;
			--scalar-radius: 0;
			--scalar-radius-lg: 0;
			--scalar-radius-xl: 0;
		}
		.light-mode {
			--scalar-background-1: #FFFDF8;
			--scalar-background-2: #F2ECE1;
			--scalar-background-3: #E9E1D2;
			--scalar-color-1: #111111;
			--scalar-color-2: #3B3631;
			--scalar-color-3: #5C554D;
			--scalar-color-accent: #8A5A12;
			--scalar-border-color: #111111;
		}
		.dark-mode {
			--scalar-background-1: #211C16;
			--scalar-background-2: #15120E;
			--scalar-background-3: #2C261E;
			--scalar-color-1: #F2ECE1;
			--scalar-color-2: #D8D0C3;
			--scalar-color-3: #B3A999;
			--scalar-color-accent: #E8A33D;
			--scalar-border-color: #F2ECE1;
		}
	`,
}

interface Scalar {
	createApiReference(element: HTMLElement, config: typeof configuration): { destroy?(): void }
}

declare global {
	interface Window {
		Scalar?: Scalar
	}
}

export const Route = createFileRoute('/reference')({
	head: () =>
		pageHead({
			title: 'API reference',
			description: 'The goethite REST API (/api/v1), from its OpenAPI document.',
			path: '/reference/',
		}),
	component: Reference,
})

function Reference() {
	const container = useRef<HTMLDivElement>(null)

	useEffect(() => {
		let app: { destroy?(): void } | undefined
		let gone = false
		function mount(scalar: Scalar) {
			if (!gone && container.current !== null) {
				app = scalar.createApiReference(container.current, configuration)
			}
		}
		if (window.Scalar === undefined) {
			const script = document.createElement('script')
			script.src = scalarUrl
			script.addEventListener('load', () => window.Scalar && mount(window.Scalar))
			document.head.append(script)
		} else {
			mount(window.Scalar)
		}
		return () => {
			gone = true
			app?.destroy?.()
		}
	}, [])

	// Scalar renders its own <main>.
	return (
		<div id="content">
			<div ref={container} />
			<noscript>
				<p className="noscript">
					The interactive reference needs JavaScript. The <a href={specUrl}>OpenAPI document</a> has the same
					content.
				</p>
			</noscript>
		</div>
	)
}
