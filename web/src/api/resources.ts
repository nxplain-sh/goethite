// Reading, saving and deleting the configuration: lists, rules, local
// records, groups, clients, schedules and settings. Every change carries the revision it is
// based on, so one made meanwhile by someone else is refused (412) rather
// than overwritten.

import { queryOptions } from '@tanstack/react-query'

import {
	api,
	call,
	ifMatch,
	type ClientSpec,
	type GroupSpec,
	type ListSpec,
	type RecordSpec,
	type RuleSpec,
	type ScheduleSpec,
	type SettingsSpec,
} from './client'

export const rulesQuery = queryOptions({
	queryKey: ['rules'],
	queryFn: () => call(api.GET('/api/v1/rules')),
})

export const recordsQuery = queryOptions({
	queryKey: ['records'],
	queryFn: () => call(api.GET('/api/v1/records')),
})

export const groupsQuery = queryOptions({
	queryKey: ['groups'],
	queryFn: () => call(api.GET('/api/v1/groups')),
})

export const allClientsQuery = queryOptions({
	queryKey: ['clients', 'all'],
	queryFn: () => call(api.GET('/api/v1/clients')),
})

export const schedulesQuery = queryOptions({
	queryKey: ['schedules'],
	queryFn: () => call(api.GET('/api/v1/schedules')),
})

export const settingsQuery = queryOptions({
	queryKey: ['settings'],
	queryFn: () => call(api.GET('/api/v1/settings')),
})

export const listQuery = (id: string) =>
	queryOptions({
		queryKey: ['lists', id],
		queryFn: () => call(api.GET('/api/v1/lists/{id}', { params: { path: { id } } })),
	})

export const ruleQuery = (id: string) =>
	queryOptions({
		queryKey: ['rules', id],
		queryFn: () => call(api.GET('/api/v1/rules/{id}', { params: { path: { id } } })),
	})

export const recordQuery = (id: string) =>
	queryOptions({
		queryKey: ['records', id],
		queryFn: () => call(api.GET('/api/v1/records/{id}', { params: { path: { id } } })),
	})

export const groupQuery = (id: string) =>
	queryOptions({
		queryKey: ['groups', id],
		queryFn: () => call(api.GET('/api/v1/groups/{id}', { params: { path: { id } } })),
	})

export const clientQuery = (id: string) =>
	queryOptions({
		queryKey: ['clients', id],
		queryFn: () => call(api.GET('/api/v1/clients/{id}', { params: { path: { id } } })),
	})

export const scheduleQuery = (id: string) =>
	queryOptions({
		queryKey: ['schedules', id],
		queryFn: () => call(api.GET('/api/v1/schedules/{id}', { params: { path: { id } } })),
	})

/** A stored resource's identity, when it is an update. */
export interface Existing {
	id: string
	revision: number
}

export function saveList(existing: Existing | undefined, spec: ListSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/lists', { body: spec }))
		: call(
				api.PUT('/api/v1/lists/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteList({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/lists/{id}', { params: { path: { id }, header: ifMatch(revision) } }),
	)
}

export function refreshLists() {
	return call(api.POST('/api/v1/lists/refresh'))
}

export function saveRule(existing: Existing | undefined, spec: RuleSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/rules', { body: spec }))
		: call(
				api.PUT('/api/v1/rules/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteRule({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/rules/{id}', { params: { path: { id }, header: ifMatch(revision) } }),
	)
}

export function saveRecord(existing: Existing | undefined, spec: RecordSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/records', { body: spec }))
		: call(
				api.PUT('/api/v1/records/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteRecord({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/records/{id}', { params: { path: { id }, header: ifMatch(revision) } }),
	)
}

export function saveGroup(existing: Existing | undefined, spec: GroupSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/groups', { body: spec }))
		: call(
				api.PUT('/api/v1/groups/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteGroup({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/groups/{id}', { params: { path: { id }, header: ifMatch(revision) } }),
	)
}

export function saveClient(existing: Existing | undefined, spec: ClientSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/clients', { body: spec }))
		: call(
				api.PUT('/api/v1/clients/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteClient({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/clients/{id}', { params: { path: { id }, header: ifMatch(revision) } }),
	)
}

export function saveSchedule(existing: Existing | undefined, spec: ScheduleSpec) {
	return existing === undefined
		? call(api.POST('/api/v1/schedules', { body: spec }))
		: call(
				api.PUT('/api/v1/schedules/{id}', {
					params: { path: { id: existing.id }, header: ifMatch(existing.revision) },
					body: spec,
				}),
			)
}

export function deleteSchedule({ id, revision }: Existing) {
	return call(
		api.DELETE('/api/v1/schedules/{id}', {
			params: { path: { id }, header: ifMatch(revision) },
		}),
	)
}

export function saveSettings(revision: number, spec: SettingsSpec) {
	return call(api.PUT('/api/v1/settings', { params: { header: ifMatch(revision) }, body: spec }))
}

/** How many audit entries one page shows. */
export const AUDIT_PAGE = 100

export const auditQuery = (before: number | undefined) =>
	queryOptions({
		queryKey: ['audit', before],
		queryFn: () =>
			call(
				api.GET('/api/v1/audit', {
					params: { query: { limit: AUDIT_PAGE, ...(before === undefined ? {} : { before }) } },
				}),
			),
		placeholderData: (previous) => previous,
	})
