// Light or dark: the system's choice unless the user picked one.

export type Theme = 'light' | 'dark'

const KEY = 'goethite.theme'

function stored(): Theme | null {
	try {
		const value = localStorage.getItem(KEY)
		return value === 'light' || value === 'dark' ? value : null
	} catch {
		return null
	}
}

/** The theme in effect. */
export function currentTheme(): Theme {
	return (
		stored() ?? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
	)
}

/** Applies the user's choice, if any. Call before the first render. */
export function applyStoredTheme(): void {
	const theme = stored()
	if (theme !== null) {
		document.documentElement.dataset['theme'] = theme
	}
}

/** Calls `listener` when the system theme changes; returns an unsubscribe. */
export function onSystemThemeChange(listener: () => void): () => void {
	const query = window.matchMedia('(prefers-color-scheme: dark)')
	query.addEventListener('change', listener)
	return () => query.removeEventListener('change', listener)
}

/** Switches to `theme` and remembers it. */
export function setTheme(theme: Theme): void {
	document.documentElement.dataset['theme'] = theme
	try {
		localStorage.setItem(KEY, theme)
	} catch {
		// Not remembered; it still applies to this page.
	}
}
