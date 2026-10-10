import { Component, type ReactNode } from 'react'

/**
 * Shows `fallback` instead of `children` once they fail to render, such as
 * a chunk that cannot be loaded after an upgrade replaced it.
 */
export class ErrorBoundary extends Component<
	{ fallback: ReactNode; children: ReactNode },
	{ failed: boolean }
> {
	override state = { failed: false }

	static getDerivedStateFromError(): { failed: boolean } {
		return { failed: true }
	}

	override render(): ReactNode {
		return this.state.failed ? this.props.fallback : this.props.children
	}
}
