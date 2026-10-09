import { describe, expect, it } from 'vitest'

import {
	clientForm,
	clientSpec,
	isClientId,
	parseClientIds,
	describeDays,
	describeWindows,
	groupForm,
	groupSpec,
	isReadOnly,
	listForm,
	listSpec,
	parseAddresses,
	ruleSpec,
	scheduleForm,
	scheduleSpec,
	toggleDay,
} from './forms'

describe('lists', () => {
	it('round-trips a URL list', () => {
		const spec = {
			name: 'Ads',
			url: 'https://lists.example/ads.txt',
			path: null,
			enabled: false,
			comment: 'Noisy.',
			managed_by: 'api' as const,
		}
		expect(listSpec(listForm(spec), spec.managed_by)).toEqual(spec)
	})

	it('sends exactly one of url and path, trimmed', () => {
		const form = { ...listForm(), name: ' Local ', source: 'path' as const, location: ' /etc/ads.txt ' }
		expect(listSpec(form)).toMatchObject({ name: 'Local', url: null, path: '/etc/ads.txt' })
	})

	it('keeps who manages it', () => {
		expect(listSpec(listForm(), 'config_file').managed_by).toBe('config_file')
		expect(listSpec(listForm()).managed_by).toBe('api')
	})
})

describe('rules', () => {
	it('trims and defaults', () => {
		expect(ruleSpec({ rule: ' ||ads.example^ ', enabled: true, comment: '' })).toEqual({
			rule: '||ads.example^',
			enabled: true,
			comment: '',
			managed_by: 'api',
		})
	})
})

describe('groups', () => {
	it('drops empty rows and repeats, and turns "always" into no schedule', () => {
		const form = {
			...groupForm(),
			name: 'Kids',
			lists: [
				{ list: 'li_a', schedule: '' },
				{ list: '', schedule: 'sc_x' },
				{ list: 'li_a', schedule: '' },
				{ list: 'li_a', schedule: 'sc_school' },
			],
		}
		expect(groupSpec(form).lists).toEqual([
			{ list: 'li_a', schedule: null },
			{ list: 'li_a', schedule: 'sc_school' },
		])
	})

	it('drops repeated blocked services', () => {
		const form = {
			...groupForm(),
			name: 'Kids',
			blockedServices: [
				{ service: 'tiktok', schedule: '' },
				{ service: 'tiktok', schedule: '' },
				{ service: '', schedule: '' },
				{ service: 'youtube', schedule: 'sc_school' },
			],
		}
		expect(groupSpec(form).blocked_services).toEqual([
			{ service: 'tiktok', schedule: null },
			{ service: 'youtube', schedule: 'sc_school' },
		])
	})

	it('round-trips', () => {
		const spec = {
			name: 'Kids',
			filtering: true,
			safe_search: true,
			lists: [{ list: 'li_a', schedule: 'sc_school' }],
			blocked_services: [
				{ service: 'tiktok', schedule: null },
				{ service: 'youtube', schedule: 'sc_school' },
			],
			comment: '',
			managed_by: 'api' as const,
		}
		expect(groupSpec(groupForm(spec), 'api')).toEqual(spec)
	})
})

describe('clients', () => {
	it('reads addresses one per line, or separated by commas and spaces, without repeats', () => {
		expect(parseAddresses(' 192.168.1.23\n192.168.1.0/24, fd00::23  192.168.1.23\n\n')).toEqual([
			'192.168.1.23',
			'192.168.1.0/24',
			'fd00::23',
		])
		expect(parseAddresses('   ')).toEqual([])
	})

	it('reads client IDs lowercase and knows valid ones', () => {
		expect(parseClientIds('Anna-Phone\nkid-1, kid-1')).toEqual(['anna-phone', 'kid-1'])
		for (const valid of ['a', 'anna-phone', '0', 'x'.repeat(63)]) {
			expect(isClientId(valid)).toBe(true)
		}
		for (const invalid of ['', '-a', 'a-', 'a.b', 'a_b', 'Anna', 'x'.repeat(64)]) {
			expect(isClientId(invalid)).toBe(false)
		}
	})

	it('round-trips', () => {
		const spec = {
			name: 'Tablet',
			addresses: ['192.168.1.23', 'fd00::23'],
			ids: ['tablet'],
			group: 'gr_kids',
			comment: '',
			managed_by: 'api' as const,
		}
		expect(clientSpec(clientForm(spec), 'api')).toEqual(spec)
		expect(clientForm().group).toBe('default')
	})
})

describe('schedules', () => {
	it('shows 24:00 as 00:00 and sends it back as 24:00', () => {
		const spec = {
			name: 'Evenings',
			time_zone: 'Europe/Berlin',
			windows: [{ days: ['sun' as const, 'mon' as const], start: '18:00', end: '24:00' }],
			comment: '',
			managed_by: 'api' as const,
		}
		const form = scheduleForm(spec)
		expect(form.windows[0]?.end).toBe('00:00')
		// Days come back in week order.
		expect(form.windows[0]?.days).toEqual(['mon', 'sun'])
		expect(scheduleSpec(form, 'api').windows).toEqual([
			{ days: ['mon', 'sun'], start: '18:00', end: '24:00' },
		])
	})

	it('toggles days in week order', () => {
		const window = { days: ['wed' as const], start: '08:00', end: '09:00' }
		expect(toggleDay(window, 'mon').days).toEqual(['mon', 'wed'])
		expect(toggleDay(window, 'wed').days).toEqual([])
	})

	it('describes days and windows', () => {
		expect(describeDays(['mon', 'tue', 'wed', 'thu', 'fri'])).toBe('Mon–Fri')
		expect(describeDays(['sat', 'sun'])).toBe('Sat, Sun')
		expect(describeDays(['mon', 'wed', 'thu', 'fri', 'sun'])).toBe('Mon, Wed–Fri, Sun')
		expect(describeDays(['sun', 'sat', 'fri', 'thu', 'wed', 'tue', 'mon'])).toBe('Every day')
		expect(describeWindows([{ days: ['sat'], start: '10:00', end: '12:00' }])).toBe('Sat 10:00–12:00')
	})
})

it('treats only Terraform as read-only', () => {
	expect(isReadOnly('terraform')).toBe(true)
	expect(isReadOnly('config_file')).toBe(false)
	expect(isReadOnly('api')).toBe(false)
	expect(isReadOnly(undefined)).toBe(false)
})
