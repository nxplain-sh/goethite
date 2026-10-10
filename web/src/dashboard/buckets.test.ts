// Times are in Europe/Berlin, which leaves summer time on 25 October 2026.
process.env.TZ = 'Europe/Berlin'

import { describe, expect, it } from 'vite-plus/test'

import type { StatsReport } from '../api/client'
import { buckets } from './buckets'

const HOUR = 3_600_000

/** A report ending at `to`, with `queries` and `blocked` in the hours starting at each ISO time. */
function report(to: string, hours: [string, number, number][]): StatsReport {
	return {
		from: new Date(Date.parse(to) - 720 * HOUR).toISOString(),
		to,
		hours: hours.map(([start, queries, blocked]) => ({
			start,
			counters: { queries, blocked } as StatsReport['hours'][number]['counters'],
		})),
	} as StatsReport
}

describe('buckets', () => {
	it('makes one bar per hour, the last holding the end, and adds hours up', () => {
		const data = buckets(
			report('2026-10-08T15:20:00Z', [
				['2026-10-08T15:00:00Z', 7, 2],
				['2026-10-08T14:00:00Z', 3, 0],
				['2026-10-07T10:00:00Z', 99, 99],
			]),
			24,
			1,
		)
		expect(data).toHaveLength(24)
		const last = data[23]
		expect(last?.start.toISOString()).toBe('2026-10-08T15:00:00.000Z')
		expect(last?.label).toBe('17:00')
		expect([last?.queries, last?.blocked]).toEqual([7, 2])
		expect(data[22]?.queries).toBe(3)
		// Older than the range: left out.
		expect(data.reduce((sum, bucket) => sum + bucket.queries, 0)).toBe(10)
	})

	it('aligns six-hour bars to quarters of the local day', () => {
		const data = buckets(report('2026-10-08T15:20:00Z', [['2026-10-08T09:00:00Z', 4, 1]]), 168, 6)
		expect(data).toHaveLength(28)
		const last = data[27]
		// 17:20 in Berlin falls in the 12:00 to 18:00 bar.
		expect(last?.title).toContain('12:00–18:00')
		expect(last?.queries).toBe(0)
		// 11:00 in Berlin: the 06:00 to 12:00 bar.
		expect(data[26]?.queries).toBe(4)
	})

	it('keeps daily bars on local midnights across a daylight saving change', () => {
		const data = buckets(
			report('2026-10-27T10:00:00Z', [
				// 23:30 on the 25th in Berlin, an hour after the clocks went back.
				['2026-10-25T22:00:00Z', 5, 0],
			]),
			720,
			24,
		)
		expect(data).toHaveLength(30)
		for (const bucket of data) {
			expect([bucket.start.getHours(), bucket.start.getMinutes()]).toEqual([0, 0])
		}
		const day = data.find((bucket) => bucket.start.getDate() === 25)
		expect(day && (day.end.getTime() - day.start.getTime()) / HOUR).toBe(25)
		expect(day?.queries).toBe(5)
	})
})
