import type { QueryEntry } from './api/client'

const integer = new Intl.NumberFormat()

/** 12,345 */
export function count(value: number): string {
	return integer.format(value)
}

/** 12.3 %, or a dash for nothing. */
export function percent(part: number, whole: number): string {
	return whole > 0 ? `${((part * 100) / whole).toFixed(1)} %` : '–'
}

/** Microseconds as milliseconds. */
export function millis(micros: number): string {
	const ms = micros / 1000
	return `${ms.toFixed(ms < 10 ? 1 : 0)} ms`
}

/** Bytes as KiB or MiB. */
export function bytes(value: number): string {
	return value < 1024 * 1024
		? `${(value / 1024).toFixed(1)} KiB`
		: `${(value / (1024 * 1024)).toFixed(1)} MiB`
}

/** 14:03:59 */
export function clock(iso: string): string {
	return new Date(iso).toLocaleTimeString([], { hour12: false })
}

/** 14:03:59 today, Oct 6, 14:03:59 on other days. */
export function moment(iso: string): string {
	const date = new Date(iso)
	if (date.toDateString() === new Date().toDateString()) {
		return clock(iso)
	}
	return date.toLocaleString([], {
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: false,
	})
}

/** Oct 8, 14:03 */
export function dateTime(iso: string): string {
	return new Date(iso).toLocaleString([], {
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
		hour12: false,
	})
}

/** How a query arrived, as people call it. */
export const PROTOCOL_LABEL: Record<QueryEntry['protocol'], string> = {
	udp: 'UDP',
	tcp: 'TCP',
	dot: 'DoT',
	doh: 'DoH',
	doq: 'DoQ',
	odoh: 'ODoH',
}
