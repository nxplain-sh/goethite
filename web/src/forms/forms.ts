// What the editors show and send: forms for lists, rules, local records,
// groups, clients and schedules, and the specs goethite stores. Pure functions, so they
// are tested without a browser (forms.test.ts).

import type {
	ClientSpec,
	GroupSpec,
	ListSpec,
	ManagedBy,
	RecordKind,
	RecordSpec,
	RuleSpec,
	ScheduleSpec,
	Weekday,
	Window,
} from '../api/client'

/** Who manages a resource, for people. */
export const MANAGED_LABEL: Record<ManagedBy, string> = {
	api: 'API',
	config_file: 'Config file',
}

// Saving keeps who manages a resource: editing a list from the config file
// here must not make it the API's.
function managed(managedBy: ManagedBy | undefined): ManagedBy {
	return managedBy ?? 'api'
}

// --- Lists ---------------------------------------------------------------

export interface ListForm {
	name: string
	source: 'url' | 'path'
	location: string
	enabled: boolean
	comment: string
}

export function listForm(spec?: ListSpec): ListForm {
	return {
		name: spec?.name ?? '',
		source: spec?.path != null ? 'path' : 'url',
		location: spec?.path ?? spec?.url ?? '',
		enabled: spec?.enabled ?? true,
		comment: spec?.comment ?? '',
	}
}

export function listSpec(form: ListForm, managedBy?: ManagedBy): ListSpec {
	const location = form.location.trim()
	return {
		name: form.name.trim(),
		url: form.source === 'url' ? location : null,
		path: form.source === 'path' ? location : null,
		enabled: form.enabled,
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

// --- Rules ---------------------------------------------------------------

export interface RuleForm {
	rule: string
	enabled: boolean
	comment: string
}

export function ruleForm(spec?: RuleSpec): RuleForm {
	return { rule: spec?.rule ?? '', enabled: spec?.enabled ?? true, comment: spec?.comment ?? '' }
}

export function ruleSpec(form: RuleForm, managedBy?: ManagedBy): RuleSpec {
	return {
		rule: form.rule.trim(),
		enabled: form.enabled,
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

// --- Local records -------------------------------------------------------

export interface RecordForm {
	name: string
	kind: RecordKind
	value: string
	/** Seconds, as typed. */
	ttl: string
	enabled: boolean
	comment: string
}

export function recordForm(spec?: RecordSpec): RecordForm {
	return {
		name: spec?.name ?? '',
		kind: spec?.type ?? 'A',
		value: spec?.value ?? '',
		ttl: String(spec?.ttl ?? 300),
		enabled: spec?.enabled ?? true,
		comment: spec?.comment ?? '',
	}
}

export function recordSpec(form: RecordForm, managedBy?: ManagedBy): RecordSpec {
	return {
		name: form.name.trim().toLowerCase(),
		type: form.kind,
		value: form.kind === 'CNAME' ? form.value.trim().toLowerCase() : form.value.trim(),
		ttl: Number(form.ttl),
		enabled: form.enabled,
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

/** What a record's value must be, for the form's hint. */
export function recordValueHint(kind: RecordKind): string {
	switch (kind) {
		case 'A':
			return 'An IPv4 address, such as 192.168.1.10.'
		case 'AAAA':
			return 'An IPv6 address, such as fd00::10.'
		case 'CNAME':
			return 'Another name, which answers for this one; goethite resolves it like any other name.'
	}
}

/** Whether a TTL, as typed, is a whole number of seconds up to a day. */
export function isRecordTtl(ttl: string): boolean {
	const seconds = Number(ttl)
	return ttl.trim() !== '' && Number.isInteger(seconds) && seconds >= 0 && seconds <= 86_400
}

// --- Groups --------------------------------------------------------------

/** A list a group uses, and the schedule it applies during ('' = always). */
export interface GroupListForm {
	list: string
	schedule: string
}

/** A service a group blocks, and the schedule it is blocked during ('' = always). */
export interface BlockedServiceForm {
	service: string
	schedule: string
}

export interface GroupForm {
	name: string
	filtering: boolean
	safeSearch: boolean
	lists: GroupListForm[]
	blockedServices: BlockedServiceForm[]
	comment: string
}

export function groupForm(spec?: GroupSpec): GroupForm {
	return {
		name: spec?.name ?? '',
		filtering: spec?.filtering ?? true,
		safeSearch: spec?.safe_search ?? false,
		lists: (spec?.lists ?? []).map((entry) => ({ list: entry.list, schedule: entry.schedule ?? '' })),
		blockedServices: (spec?.blocked_services ?? []).map((entry) => ({
			service: entry.service,
			schedule: entry.schedule ?? '',
		})),
		comment: spec?.comment ?? '',
	}
}

export function groupSpec(form: GroupForm, managedBy?: ManagedBy): GroupSpec {
	// Rows left empty are dropped, and goethite refuses the same list and
	// schedule twice, so repeats are dropped too.
	const seen = new Set<string>()
	const lists = form.lists.flatMap((entry) => {
		const key = `${entry.list}\u0000${entry.schedule}`
		if (entry.list === '' || seen.has(key)) return []
		seen.add(key)
		return [{ list: entry.list, schedule: entry.schedule === '' ? null : entry.schedule }]
	})
	const blocked = new Set<string>()
	const blockedServices = form.blockedServices.flatMap((entry) => {
		const key = `${entry.service}\u0000${entry.schedule}`
		if (entry.service === '' || blocked.has(key)) return []
		blocked.add(key)
		return [{ service: entry.service, schedule: entry.schedule === '' ? null : entry.schedule }]
	})
	return {
		name: form.name.trim(),
		filtering: form.filtering,
		safe_search: form.safeSearch,
		lists,
		blocked_services: blockedServices,
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

// --- Clients -------------------------------------------------------------

export interface ClientForm {
	name: string
	addresses: string
	ids: string
	group: string
	comment: string
}

/** The default group, which every goethite has. */
export const DEFAULT_GROUP = 'default'

export function clientForm(spec?: ClientSpec): ClientForm {
	return {
		name: spec?.name ?? '',
		addresses: (spec?.addresses ?? []).join('\n'),
		ids: (spec?.ids ?? []).join('\n'),
		group: spec?.group ?? DEFAULT_GROUP,
		comment: spec?.comment ?? '',
	}
}

/** Addresses typed one per line, or separated by commas or spaces. */
export function parseAddresses(text: string): string[] {
	return [...new Set(text.split(/[\s,]+/).filter((part) => part !== ''))]
}

/** Client IDs typed like addresses; lowercase, as goethite wants them. */
export function parseClientIds(text: string): string[] {
	return parseAddresses(text.toLowerCase())
}

/** 1 to 63 lowercase letters, digits and hyphens, not at either end. */
export function isClientId(id: string): boolean {
	return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(id)
}

/**
 * Access list entries, typed like addresses: addresses, networks and client
 * IDs, lowercase.
 */
export function parseAccessEntries(text: string): string[] {
	return parseAddresses(text.toLowerCase())
}

/**
 * Whether an access list entry looks like an address, a network or a client
 * ID. A rough check, for the form's hint: goethite checks each one exactly
 * when the settings are saved.
 */
export function isAccessEntry(entry: string): boolean {
	const address = /^[0-9a-f.:]+(\/[0-9]{1,3})?$/.test(entry) && /[.:]/.test(entry)
	return address || isClientId(entry)
}

export function clientSpec(form: ClientForm, managedBy?: ManagedBy): ClientSpec {
	return {
		name: form.name.trim(),
		addresses: parseAddresses(form.addresses),
		ids: parseClientIds(form.ids),
		group: form.group,
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

// --- Schedules -----------------------------------------------------------

export const WEEKDAYS: readonly Weekday[] = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

export const WEEKDAY_LABEL: Record<Weekday, string> = {
	mon: 'Mon',
	tue: 'Tue',
	wed: 'Wed',
	thu: 'Thu',
	fri: 'Fri',
	sat: 'Sat',
	sun: 'Sun',
}

export interface WindowForm {
	days: Weekday[]
	start: string
	end: string
}

export interface ScheduleForm {
	name: string
	timeZone: string
	windows: WindowForm[]
	comment: string
}

export function newWindow(): WindowForm {
	return { days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '08:00', end: '17:00' }
}

/** The browser's time zone, if it has one, else UTC. */
export function localTimeZone(): string {
	return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
}

export function scheduleForm(spec?: ScheduleSpec): ScheduleForm {
	return {
		name: spec?.name ?? '',
		timeZone: spec?.time_zone ?? localTimeZone(),
		// A time input cannot show 24:00; 00:00 as an end means the same.
		windows: (spec?.windows ?? [newWindow()]).map((window) => ({
			days: sortDays(window.days),
			start: window.start,
			end: window.end === '24:00' ? '00:00' : window.end,
		})),
		comment: spec?.comment ?? '',
	}
}

export function scheduleSpec(form: ScheduleForm, managedBy?: ManagedBy): ScheduleSpec {
	return {
		name: form.name.trim(),
		time_zone: form.timeZone.trim(),
		// An end of 00:00 is midnight at the end of the day: 21:00–00:00
		// is the evening, 00:00–00:00 the whole day.
		windows: form.windows.map((window) => ({
			days: sortDays(window.days),
			start: window.start,
			end: window.end === '00:00' ? '24:00' : window.end,
		})),
		comment: form.comment.trim(),
		managed_by: managed(managedBy),
	}
}

export function sortDays(days: readonly Weekday[]): Weekday[] {
	return WEEKDAYS.filter((day) => days.includes(day))
}

/** Turns a day on or off in a window. */
export function toggleDay(window: WindowForm, day: Weekday): WindowForm {
	const days = window.days.includes(day)
		? window.days.filter((other) => other !== day)
		: [...window.days, day]
	return { ...window, days: sortDays(days) }
}

/** Days for people: "Mon–Fri", "Sat, Sun", "Every day". */
export function describeDays(days: readonly Weekday[]): string {
	const sorted = sortDays(days)
	if (sorted.length === 7) return 'Every day'
	const runs: Weekday[][] = []
	for (const day of sorted) {
		const run = runs[runs.length - 1]
		const last = run?.[run.length - 1]
		if (run !== undefined && last !== undefined && WEEKDAYS.indexOf(day) === WEEKDAYS.indexOf(last) + 1) {
			run.push(day)
		} else {
			runs.push([day])
		}
	}
	return runs
		.flatMap((run) => {
			const first = run[0]
			const last = run[run.length - 1]
			if (first === undefined || last === undefined) return []
			if (run.length >= 3) return [`${WEEKDAY_LABEL[first]}–${WEEKDAY_LABEL[last]}`]
			return run.map((day) => WEEKDAY_LABEL[day])
		})
		.join(', ')
}

/** Windows for people: "Mon–Fri 08:00–15:00; Sat 10:00–12:00". */
export function describeWindows(windows: readonly Window[]): string {
	return windows.map((window) => `${describeDays(window.days)} ${window.start}–${window.end}`).join('; ')
}
