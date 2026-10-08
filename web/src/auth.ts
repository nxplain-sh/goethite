// The admin token, when the node needs one.
//
// It lives in this tab's sessionStorage: it survives a reload but not closing
// the tab, and other sites cannot read it. Scripts on this page could, which
// is why the page runs under a strict Content Security Policy with no inline
// or third-party code.

const KEY = 'goethite.token'

function stored(): string | null {
	try {
		return sessionStorage.getItem(KEY)
	} catch {
		return null
	}
}

/** Remembers the token for this tab. */
export function setToken(value: string): void {
	try {
		sessionStorage.setItem(KEY, value)
	} catch {
		// Storage is off: the token lasts until the page reloads.
		memory = value
	}
}

/** Forgets the token. */
export function clearToken(): void {
	memory = null
	try {
		sessionStorage.removeItem(KEY)
	} catch {
		// Nothing stored.
	}
}

let memory: string | null = null

/** The token, if the user has signed in. */
export function currentToken(): string | null {
	return stored() ?? memory
}

/** Whether `value` looks like a token from `goethite token`. */
export function looksLikeToken(value: string): boolean {
	return /^gth_[0-9a-f]{64}$/.test(value)
}

/** Where to go after signing in: a path on this site, nothing else. */
export function safeRedirect(value: unknown): string | undefined {
	return typeof value === 'string' &&
		value.startsWith('/') &&
		!value.startsWith('//') &&
		!value.includes('\\')
		? value
		: undefined
}
