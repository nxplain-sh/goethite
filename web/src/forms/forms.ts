// What the editors show and send: forms for lists, rules, groups, clients
// and schedules, and the specs goethite stores. Pure functions, so they
// are tested without a browser (forms.test.ts).

import type {
	ClientSpec,
	GroupSpec,
	ListSpec,
	ManagedBy,
	RuleSpec,
	ScheduleSpec,
	Weekday,
	Window,
} from '../api/client'

/** Who manages a resource, for people. */
export const MANAGED_LABEL: Record<ManagedBy, string> = {
	api: 'API',
	terraform: 'Terraform',
	config_file: 'Config file',
}

/** Resources Terraform manages are read-only here: change them there. */
export function isReadOnly(managedBy: ManagedBy | undefined): boolean {
	return managedBy === 'terraform'
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

// --- Groups --------------------------------------------------------------

/** A list a group uses, and the schedule it applies during ('' = always). */
export interface GroupListForm {
	list: string
	schedule: string
}

export interface GroupForm {
	name: string
	filtering: boolean
	safeSearch: boolean
	lists: GroupListForm[]
	comment: string
}

export function groupForm(spec?: GroupSpec): GroupForm {
	return {
		name: spec?.name ?? '',
		filtering: spec?.filtering ?? true,
		safeSearch: spec?.safe_search ?? false,
		lists: (spec?.lists ?? []).map((entry) => ({ list: entry.list, schedule: entry.schedule ?? '' })),
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
	return {
		name: form.name.trim(),
		filtering: form.filtering,
		safe_search: form.safeSearch,
		lists,
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
	return windows
		.map((window) => `${describeDays(window.days)} ${window.start}–${window.end}`)
		.join('; ')
}
