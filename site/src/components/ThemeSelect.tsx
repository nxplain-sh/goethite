import { useEffect, useState } from 'react'

type Theme = 'auto' | 'light' | 'dark'

const key = 'goethite-theme'

function saved(): Theme {
	try {
		const theme = localStorage.getItem(key)
		return theme === 'light' || theme === 'dark' ? theme : 'auto'
	} catch {
		return 'auto'
	}
}

/** Light, dark, or whatever the system prefers. The boot script in __root.tsx applies it on load. */
export function ThemeSelect() {
	// The server cannot know the choice, so the first render says "auto" like it did.
	const [theme, setTheme] = useState<Theme>('auto')
	useEffect(() => setTheme(saved()), [])

	function choose(next: Theme) {
		setTheme(next)
		const root = document.documentElement
		if (next === 'auto') {
			delete root.dataset.theme
		} else {
			root.dataset.theme = next
		}
		try {
			if (next === 'auto') {
				localStorage.removeItem(key)
			} else {
				localStorage.setItem(key, next)
			}
		} catch {
			// Storage can be off; the choice then lasts until the next page load.
		}
	}

	return (
		<label className="theme needs-js">
			<span className="sr-only">Theme</span>
			<select value={theme} onChange={(event) => choose(event.target.value as Theme)}>
				<option value="auto">Auto</option>
				<option value="light">Light</option>
				<option value="dark">Dark</option>
			</select>
		</label>
	)
}
