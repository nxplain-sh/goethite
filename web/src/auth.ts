// Signing in and out.
//
// The session is an HttpOnly cookie the server sets: page scripts cannot
// read it, and this module never holds it. What lives here is where to go
// after signing in, and how to sign out.

import { api } from './api/client'

/** Where to go after signing in: a path on this site, nothing else. */
export function safeRedirect(value: unknown): string | undefined {
	return typeof value === 'string' &&
		value.startsWith('/') &&
		!value.startsWith('//') &&
		!value.includes('\\')
		? value
		: undefined
}

/** Signs out on the server; the cookie is cleared there. */
export async function signOut(): Promise<void> {
	try {
		await api.POST('/api/v1/auth/logout')
	} catch {
		// Already signed out: nothing to end.
	}
}
