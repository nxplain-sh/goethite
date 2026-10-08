// The DNS leak test's verdict, from what goethite saw: which of the test's
// names reached it, from where and how.

import type { Schemas } from '../api/client'

export type LeakTest = Schemas['LeakTest']
export type LeakLookup = Schemas['LeakLookup']

export type Verdict = 'none' | 'partial' | 'all'

/** How many of the test's names reached goethite, in words for the badge. */
export function verdict(test: LeakTest): Verdict {
	if (test.reached === 0) {
		return 'none'
	}
	return test.reached >= test.names.length ? 'all' : 'partial'
}

/** The distinct values of `pick` over the lookups, in the order seen. */
export function distinct<T>(lookups: LeakLookup[], pick: (lookup: LeakLookup) => T | null | undefined): T[] {
	const seen: T[] = []
	for (const lookup of lookups) {
		const value = pick(lookup)
		if (value != null && !seen.includes(value)) {
			seen.push(value)
		}
	}
	return seen
}

/**
 * Whether the lookups came from another address than the one the test was
 * started from: something in between (often the router) may forward them,
 * or the device used another address family. `null` when it cannot tell.
 */
export function fromElsewhere(test: LeakTest): string[] | null {
	if (test.requested_by == null || test.lookups.length === 0) {
		return null
	}
	const others = distinct(test.lookups, (lookup) => lookup.address).filter(
		(address) => address !== test.requested_by,
	)
	return others
}

/** The host to load an image from for a test name: without the final dot. */
export function host(name: string): string {
	return name.endsWith('.') ? name.slice(0, -1) : name
}
