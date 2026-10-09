// What applying a preset, or switching between lists that do the same job,
// changes: worked out here, without I/O, so it can be shown before it is done.

import type { Group, GroupList, List, Preset, RecommendedList } from '../api/client'

/** The changes to make, in order: lists to create, to turn on, to turn off, then the groups. */
export interface Plan {
	/** Recommended lists the node does not have yet, created turned on. */
	create: RecommendedList[]
	/** The node's lists to turn on. */
	enable: List[]
	/** The node's lists to turn off. */
	disable: List[]
	/** Each group to change, with its new lists; `created` stands for lists made in this plan. */
	groups: { group: Group; lists: PlannedEntry[] }[]
	/** For people: what joins and what leaves each group. */
	summary: { group: Group; joins: string[]; leaves: string[] }[]
}

/** A list in a group: one the node has, or one this plan creates. */
export type PlannedEntry =
	| { list: string; schedule: string | null }
	| { created: RecommendedList; schedule: string | null }

/** The node's list for a recommended one, if it has it. */
export function nodeList(lists: List[], item: RecommendedList): List | undefined {
	return lists.find((list) => list.spec.url === item.url)
}

/** The recommended list a node's list is, if it is one. */
export function catalogEntry(catalog: RecommendedList[], list: List): RecommendedList | undefined {
	return catalog.find((item) => item.url === list.spec.url)
}

function entries(group: Group): GroupList[] {
	return group.spec.lists ?? []
}

function sameEntries(a: PlannedEntry[], b: GroupList[]): boolean {
	return (
		a.length === b.length &&
		a.every((entry, at) => 'list' in entry && entry.list === b[at]?.list && entry.schedule === (b[at]?.schedule ?? null))
	)
}

/**
 * Applying `preset` to `group`: its lists join the group (created or turned on
 * as needed), and recommended lists the preset does not have leave it, and
 * are turned off if no other group (in `groups`) uses them. Lists that are not
 * recommended ones stay as they are.
 */
export function planPreset(
	catalog: RecommendedList[],
	preset: Preset,
	lists: List[],
	group: Group,
	groups: Group[],
): Plan {
	const wanted = preset.lists
		.map((id) => catalog.find((item) => item.id === id))
		.filter((item): item is RecommendedList => item !== undefined)
	const create = wanted.filter((item) => nodeList(lists, item) === undefined)
	const enable = wanted
		.map((item) => nodeList(lists, item))
		.filter((list): list is List => list !== undefined && list.spec.enabled === false)
	const wantedIds = new Set(wanted.map((item) => nodeList(lists, item)?.id).filter((id) => id !== undefined))
	const byId = new Map(lists.map((list) => [list.id, list]))
	const joins: string[] = []
	const leaves: string[] = []
	const kept: PlannedEntry[] = []
	for (const entry of entries(group)) {
		const list = byId.get(entry.list)
		const recommended = list !== undefined && catalogEntry(catalog, list) !== undefined
		if (recommended && !wantedIds.has(entry.list)) {
			if (!leaves.includes(list.spec.name)) leaves.push(list.spec.name)
			continue
		}
		kept.push({ list: entry.list, schedule: entry.schedule ?? null })
	}
	for (const item of wanted) {
		const list = nodeList(lists, item)
		const always = list !== undefined && kept.some((entry) => 'list' in entry && entry.list === list.id && entry.schedule === null)
		if (always) continue
		kept.push(list === undefined ? { created: item, schedule: null } : { list: list.id, schedule: null })
		joins.push(item.name)
	}
	const changed = !sameEntries(kept, entries(group))
	const usedElsewhere = new Set(
		groups.filter((other) => other.id !== group.id).flatMap((other) => entries(other).map((e) => e.list)),
	)
	const disable = entries(group)
		.map((entry) => byId.get(entry.list))
		.filter(
			(list): list is List =>
				list !== undefined &&
				list.spec.enabled !== false &&
				catalogEntry(catalog, list) !== undefined &&
				!wantedIds.has(list.id) &&
				!usedElsewhere.has(list.id),
		)
		.filter((list, at, all) => all.findIndex((other) => other.id === list.id) === at)
	return {
		create,
		enable,
		disable,
		groups: changed ? [{ group, lists: kept }] : [],
		summary:
			changed || create.length > 0 || enable.length > 0 || disable.length > 0
				? [{ group, joins, leaves }]
				: [],
	}
}

/** The node's lists in use (turned on) that `item` excludes. */
export function excludedInUse(catalog: RecommendedList[], item: RecommendedList, lists: List[]): List[] {
	return item.excludes
		.map((id) => catalog.find((other) => other.id === id))
		.map((other) => (other === undefined ? undefined : nodeList(lists, other)))
		.filter((list): list is List => list !== undefined && list.spec.enabled !== false)
}

/**
 * Switching to `item` from the lists it excludes: it takes their place in
 * every group that uses them (with the same schedules), or joins `fallback`
 * if none does, and they are turned off.
 */
export function planSwitch(
	catalog: RecommendedList[],
	item: RecommendedList,
	lists: List[],
	groups: Group[],
	fallback: Group | undefined,
): Plan {
	const replaced = excludedInUse(catalog, item, lists)
	const replacedIds = new Set(replaced.map((list) => list.id))
	const existing = nodeList(lists, item)
	const create = existing === undefined ? [item] : []
	const enable = existing !== undefined && existing.spec.enabled === false ? [existing] : []
	const entry = (schedule: string | null): PlannedEntry =>
		existing === undefined ? { created: item, schedule } : { list: existing.id, schedule }
	const planned: Plan['groups'] = []
	const summary: Plan['summary'] = []
	for (const group of groups) {
		const current = entries(group)
		if (!current.some((e) => replacedIds.has(e.list))) continue
		const next: PlannedEntry[] = []
		const schedules = new Set<string | null>()
		for (const e of current) {
			const schedule = e.schedule ?? null
			if (replacedIds.has(e.list) || (existing !== undefined && e.list === existing.id)) {
				if (!schedules.has(schedule)) next.push(entry(schedule))
				schedules.add(schedule)
				continue
			}
			next.push({ list: e.list, schedule })
		}
		planned.push({ group, lists: next })
		const leaves = replaced.filter((list) => current.some((e) => e.list === list.id)).map((list) => list.spec.name)
		summary.push({ group, joins: [item.name], leaves })
	}
	if (planned.length === 0 && fallback !== undefined) {
		const inFallback = existing !== undefined && entries(fallback).some((e) => e.list === existing.id)
		if (!inFallback) {
			planned.push({ group: fallback, lists: [...entries(fallback).map((e) => ({ list: e.list, schedule: e.schedule ?? null })), entry(null)] })
			summary.push({ group: fallback, joins: [item.name], leaves: [] })
		}
	}
	return { create, enable, disable: replaced, groups: planned, summary }
}

/** The base lists turned on, which overlap if there is more than one. */
export function baseListsInUse(catalog: RecommendedList[], lists: List[]): RecommendedList[] {
	return catalog.filter((item) => {
		const list = nodeList(lists, item)
		return item.category === 'base' && list !== undefined && list.spec.enabled !== false
	})
}
