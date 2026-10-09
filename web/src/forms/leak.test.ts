import { describe, expect, it } from 'vitest'

import { distinct, fromElsewhere, host, type LeakLookup, type LeakTest, verdict } from './leak'

function lookup(probe: number, address = '192.0.2.10', protocol: LeakLookup['protocol'] = 'udp'): LeakLookup {
	return {
		probe,
		time: '2026-10-08T12:00:00Z',
		address,
		protocol,
		qtype: 'A',
		filtering: true,
	}
}

function test(reached: number, lookups: LeakLookup[], from: string | null = '192.0.2.10'): LeakTest {
	return {
		id: 'ab',
		names: Array.from({ length: 8 }, (_, i) => `ab-${i + 1}.leak.goethite.test.`),
		created_at: '2026-10-08T12:00:00Z',
		expires_at: '2026-10-08T13:00:00Z',
		...(from === null ? {} : { requested_by: from }),
		reached,
		lookups,
	}
}

describe('leak test verdicts', () => {
	it('tells none, some and all apart', () => {
		expect(verdict(test(0, []))).toBe('none')
		expect(verdict(test(3, [lookup(1), lookup(2), lookup(3)]))).toBe('partial')
		const all = Array.from({ length: 8 }, (_, i) => lookup(i + 1))
		expect(verdict(test(8, all))).toBe('all')
	})

	it('notices lookups from another address', () => {
		expect(fromElsewhere(test(1, [lookup(1)]))).toEqual([])
		expect(fromElsewhere(test(2, [lookup(1, '192.0.2.1'), lookup(2, '192.0.2.1')]))).toEqual(['192.0.2.1'])
		expect(fromElsewhere(test(0, []))).toBeNull()
		expect(fromElsewhere(test(1, [lookup(1)], null))).toBeNull()
	})

	it('lists protocols once each', () => {
		const lookups = [lookup(1, 'a', 'doh'), lookup(2, 'a', 'doh'), lookup(3, 'a', 'udp')]
		expect(distinct(lookups, (l) => l.protocol)).toEqual(['doh', 'udp'])
	})

	it('loads images from the name without its final dot', () => {
		expect(host('ab-1.leak.goethite.test.')).toBe('ab-1.leak.goethite.test')
	})
})
