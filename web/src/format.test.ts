import { describe, expect, it } from 'vite-plus/test'

import { ago } from './format'

describe('ago', () => {
	const now = Date.parse('2026-10-10T12:00:00Z')

	it('counts in the largest whole unit', () => {
		expect(ago('2026-10-10T12:00:00Z', now)).toBe('just now')
		expect(ago('2026-10-10T11:59:56Z', now)).toBe('4 s ago')
		expect(ago('2026-10-10T11:57:00Z', now)).toBe('3 min ago')
		expect(ago('2026-10-10T09:30:00Z', now)).toBe('2 h ago')
		expect(ago('2026-10-05T12:00:00Z', now)).toBe('5 d ago')
	})

	it('says just now for a time a skewed clock puts ahead', () => {
		expect(ago('2026-10-10T12:00:03Z', now)).toBe('just now')
	})
})
