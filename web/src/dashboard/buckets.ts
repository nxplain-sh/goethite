import type { StatsReport } from '../api/client'

/** One bar: a time window and what was asked in it. */
export interface Bucket {
	id: string
	start: Date
	end: Date
	/** Under the bar, such as `14:00`. */
	label: string
	/** In the tooltip, such as `Oct 8, 14:00–15:00`. */
	title: string
	queries: number
	blocked: number
}

const time = (date: Date) =>
	date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
const day = (date: Date) => date.toLocaleDateString([], { month: 'short', day: 'numeric' })
const weekday = (date: Date) => date.toLocaleDateString([], { weekday: 'short' })

/**
 * The report's hourly counts in `hours / each` buckets of `each` hours,
 * aligned to local time (whole hours, quarters of a day, midnights), the
 * last one holding the report's end. Steps go by local time, so a day
 * across a daylight saving change keeps its midnights.
 */
export function buckets(report: StatsReport, hours: number, each: number): Bucket[] {
	const last = new Date(report.to)
	last.setMinutes(0, 0, 0)
	last.setHours(last.getHours() - (last.getHours() % each))
	const total = Math.max(1, Math.floor(hours / each))
	const shifted = (date: Date, by: number) => {
		const copy = new Date(date)
		copy.setHours(copy.getHours() + by)
		return copy
	}
	const result: Bucket[] = []
	for (let index = 0; index < total; index++) {
		const start = shifted(last, -(total - 1 - index) * each)
		const end = shifted(start, each)
		const label = each === 1 ? time(start) : each < 24 ? `${weekday(start)} ${time(start)}` : day(start)
		const title =
			each < 24 ? `${weekday(start)} ${day(start)}, ${time(start)}–${time(end)}` : `${weekday(start)} ${day(start)}`
		result.push({ id: start.toISOString(), start, end, label, title, queries: 0, blocked: 0 })
	}
	for (const point of report.hours) {
		const at = Date.parse(point.start)
		const bucket = result.find((candidate) => candidate.start.getTime() <= at && at < candidate.end.getTime())
		if (bucket) {
			bucket.queries += point.counters.queries
			bucket.blocked += point.counters.blocked
		}
	}
	return result
}
