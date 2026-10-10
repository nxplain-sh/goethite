import { describe, expect, it } from 'vite-plus/test'

import type { Group, List, Preset, RecommendedList } from '../api/client'
import { baseListsInUse, excludedInUse, planPreset, planSwitch } from './recommended'

function item(id: string, category: RecommendedList['category'], excludes: string[] = []): RecommendedList {
	return {
		id,
		name: id,
		maintainer: 'm',
		description: 'd',
		url: `https://lists.example/${id}.txt`,
		homepage: 'https://lists.example',
		license: 'MIT',
		category,
		recommended: false,
		default: false,
		excludes,
	}
}

const catalog = [
	item('normal', 'base'),
	item('oisd', 'base'),
	item('tif-mini', 'security', ['tif']),
	item('tif', 'security', ['tif-mini']),
	item('fake', 'security'),
]

function list(id: string, url: string, enabled = true): List {
	return {
		id,
		revision: 1,
		created_at: '2026-10-08T00:00:00Z',
		updated_at: '2026-10-08T00:00:00Z',
		spec: { name: id, url, enabled, comment: '', managed_by: 'api' },
	}
}

function group(id: string, lists: { list: string; schedule?: string | null }[]): Group {
	return {
		id,
		revision: 3,
		created_at: '2026-10-08T00:00:00Z',
		updated_at: '2026-10-08T00:00:00Z',
		spec: { name: id, lists, managed_by: 'api' },
	}
}

const url = (id: string) => `https://lists.example/${id}.txt`

describe('presets', () => {
	const strict: Preset = {
		id: 'strict',
		name: 'Strict',
		description: '',
		lists: ['oisd', 'tif', 'fake'],
		default: false,
	}

	it('swaps recommended lists, keeps the rest, turns off what no group uses', () => {
		const lists = [
			list('li_normal', url('normal')),
			list('li_mini', url('tif-mini')),
			list('li_fake', url('fake'), false),
			list('li_own', 'https://mine.example/list.txt'),
		]
		const kids = group('gr_kids', [
			{ list: 'li_normal' },
			{ list: 'li_mini' },
			{ list: 'li_own', schedule: 'sc_1' },
		])
		const other = group('default', [{ list: 'li_mini' }])
		const plan = planPreset(catalog, strict, lists, kids, [kids, other])
		expect(plan.create.map((i) => i.id)).toEqual(['oisd', 'tif'])
		expect(plan.enable.map((l) => l.id)).toEqual(['li_fake'])
		// TIF Mini is still the default group's; Normal is no one's any more.
		expect(plan.disable.map((l) => l.id)).toEqual(['li_normal'])
		expect(plan.groups).toHaveLength(1)
		expect(plan.groups[0]?.lists).toEqual([
			{ list: 'li_own', schedule: 'sc_1' },
			{ created: catalog[1], schedule: null },
			{ created: catalog[3], schedule: null },
			{ list: 'li_fake', schedule: null },
		])
		expect(plan.summary[0]?.joins).toEqual(['oisd', 'tif', 'fake'])
		expect(plan.summary[0]?.leaves).toEqual(['li_normal', 'li_mini'])
	})

	it('changes nothing when the group already has the preset', () => {
		const lists = [list('a', url('oisd')), list('b', url('tif')), list('c', url('fake'))]
		const same = group('default', [{ list: 'a' }, { list: 'b' }, { list: 'c' }])
		const plan = planPreset(catalog, strict, lists, same, [same])
		expect(plan).toEqual({ create: [], enable: [], disable: [], groups: [], summary: [] })
	})
})

describe('switching', () => {
	it('takes the place of what it excludes, schedules and all', () => {
		const lists = [list('li_mini', url('tif-mini')), list('li_x', url('normal'))]
		const groups = [
			group('default', [{ list: 'li_x' }, { list: 'li_mini' }]),
			group('gr_kids', [{ list: 'li_mini', schedule: 'sc_school' }]),
			group('gr_none', [{ list: 'li_x' }]),
		]
		const tif = catalog[3] as RecommendedList
		expect(excludedInUse(catalog, tif, lists).map((l) => l.id)).toEqual(['li_mini'])
		const plan = planSwitch(catalog, tif, lists, groups, groups[0])
		expect(plan.create).toEqual([tif])
		expect(plan.disable.map((l) => l.id)).toEqual(['li_mini'])
		expect(plan.groups.map((g) => g.group.id)).toEqual(['default', 'gr_kids'])
		expect(plan.groups[0]?.lists).toEqual([
			{ list: 'li_x', schedule: null },
			{ created: tif, schedule: null },
		])
		expect(plan.groups[1]?.lists).toEqual([{ created: tif, schedule: 'sc_school' }])
	})

	it('joins the fallback group when nothing used what it replaces', () => {
		const lists = [list('li_mini', url('tif-mini'))]
		const fallback = group('default', [])
		const plan = planSwitch(catalog, catalog[3] as RecommendedList, lists, [fallback], fallback)
		expect(plan.groups[0]?.lists).toEqual([{ created: catalog[3], schedule: null }])
		expect(plan.disable.map((l) => l.id)).toEqual(['li_mini'])
	})
})

describe('overlap', () => {
	it('counts the base lists turned on', () => {
		const lists = [list('a', url('normal')), list('b', url('oisd'), false), list('c', url('fake'))]
		expect(baseListsInUse(catalog, lists).map((i) => i.id)).toEqual(['normal'])
		// The store has one list per URL: turning it on is what counts.
		lists[1] = list('b', url('oisd'))
		expect(baseListsInUse(catalog, lists).map((i) => i.id)).toEqual(['normal', 'oisd'])
	})
})
