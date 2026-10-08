// The web UI end to end, against a real goethite (see e2e/serve.mjs).

import { createSocket } from 'node:dgram'

import { type APIRequestContext, expect, type Page, test } from '@playwright/test'

import { DNS_PORT, DOH_PORT, DOQ_PORT, DOT_PORT, TOKEN } from './settings.mjs'

const auth = { Authorization: `Bearer ${TOKEN}` }

/** Signs in with the admin token, as a person would. */
async function signIn(page: Page) {
	await page.goto('/login')
	await page.getByLabel('Admin token').fill(TOKEN)
	await page.getByRole('button', { name: 'Sign in' }).click()
	await expect(page.getByRole('navigation', { name: 'Pages' })).toBeVisible()
}

/** Calls the API directly, behind the UI's back. */
async function apiCall(request: APIRequestContext, method: string, path: string, body?: unknown) {
	const response = await request.fetch(path, {
		method,
		headers: auth,
		...(body === undefined ? {} : { data: body }),
	})
	expect(response.ok(), `${method} ${path}: ${response.status()} ${await response.text()}`).toBe(true)
	return response.status() === 204 ? undefined : await response.json()
}

test.beforeEach(async ({ page }) => {
	await signIn(page)
})

test('asks for the token, and refuses a wrong one', async ({ page }) => {
	await page.getByRole('button', { name: 'Sign out' }).click()
	await expect(page).toHaveURL(/\/login/)
	await page.getByLabel('Admin token').fill('gth_wrong')
	await page.getByRole('button', { name: 'Sign in' }).click()
	await expect(page.getByRole('alert')).toBeVisible()
	await expect(page).toHaveURL(/\/login/)
})

test('creates, edits and deletes a filter list, used by the default group', async ({ page, request }) => {
	await page.getByRole('link', { name: 'Lists', exact: true }).click()
	await page.getByRole('link', { name: 'New list' }).click()
	await page.getByLabel('Name').fill('E2E ads')
	await page.getByLabel('URL').fill('https://lists.example/e2e-ads.txt')
	await expect(page.getByLabel('Use it in the default group')).toBeChecked()
	await page.getByRole('button', { name: 'Create' }).click()

	await expect(page).toHaveURL(/\/lists$/)
	const row = page.getByRole('row').filter({ hasText: 'E2E ads' })
	await expect(row).toContainText('https://lists.example/e2e-ads.txt')
	const group = await apiCall(request, 'GET', '/api/v1/groups/default')
	const lists = await apiCall(request, 'GET', '/api/v1/lists')
	const created = lists.find((list: { spec: { name: string } }) => list.spec.name === 'E2E ads')
	expect(group.spec.lists.map((entry: { list: string }) => entry.list)).toContain(created.id)

	await row.getByRole('link', { name: 'E2E ads' }).click()
	await page.getByLabel('Name').fill('E2E ads, renamed')
	await page.getByLabel('Enabled').uncheck()
	await page.getByRole('button', { name: 'Save' }).click()
	await expect(page.getByRole('row').filter({ hasText: 'E2E ads, renamed' })).toContainText('OFF')

	await page.getByRole('link', { name: 'E2E ads, renamed' }).click()
	await page.getByRole('button', { name: 'Delete', exact: true }).click()
	await page.getByRole('button', { name: 'Delete this list' }).click()
	await expect(page).toHaveURL(/\/lists$/)
	await expect(page.getByRole('row').filter({ hasText: 'E2E ads' })).toHaveCount(0)
})

test('adds, filters, turns off and deletes custom rules', async ({ page }) => {
	await page.getByRole('link', { name: 'Rules', exact: true }).click()
	for (const rule of ['||e2e-one.example^', '||e2e-two.example^']) {
		await page.getByLabel('New rule').fill(rule)
		await page.getByRole('button', { name: 'Add', exact: true }).click()
		await expect(page.getByRole('row').filter({ hasText: rule })).toBeVisible()
	}
	await page.getByLabel('Filter').fill('e2e-two')
	await expect(page.getByRole('row').filter({ hasText: 'e2e-one' })).toHaveCount(0)
	const row = page.getByRole('row').filter({ hasText: '||e2e-two.example^' })
	await row.getByRole('checkbox').uncheck()
	await expect(row.getByRole('checkbox')).not.toBeChecked()
	await page.reload()
	await page.getByLabel('Filter').fill('e2e-two')
	await expect(row.getByRole('checkbox')).not.toBeChecked()

	// A rule goethite cannot use is refused, with its reason.
	await page.getByLabel('New rule').fill('! a comment')
	await page.getByRole('button', { name: 'Add', exact: true }).click()
	await expect(page.getByRole('alert')).toContainText('comment')

	await page.getByLabel('Filter').fill('e2e-')
	for (const rule of ['||e2e-one.example^', '||e2e-two.example^']) {
		const target = page.getByRole('row').filter({ hasText: rule })
		await target.getByRole('button', { name: 'Delete', exact: true }).click()
		await target.getByRole('button', { name: 'Delete this rule' }).click()
		await expect(target).toHaveCount(0)
	}
})

test('puts a client in a group that uses a list during a schedule', async ({ page, request }) => {
	const list = await apiCall(request, 'POST', '/api/v1/lists', {
		name: 'E2E social',
		url: 'https://lists.example/e2e-social.txt',
	})

	await page.getByRole('link', { name: 'Schedules', exact: true }).click()
	await page.getByRole('link', { name: 'New schedule' }).click()
	await page.getByLabel('Name').fill('E2E school')
	await page.getByLabel('Time zone').fill('Europe/Berlin')
	await page.getByLabel('From').fill('08:00')
	await page.getByLabel('Until').fill('15:00')
	await page.getByRole('button', { name: 'Create' }).click()
	await expect(page.getByRole('row').filter({ hasText: 'E2E school' })).toContainText(
		'Mon–Fri 08:00–15:00',
	)

	await page.getByRole('link', { name: 'Groups', exact: true }).click()
	await page.getByRole('link', { name: 'New group' }).click()
	await page.getByLabel('Name').fill('E2E kids')
	await page.getByLabel('Safe search').check()
	await page.getByRole('button', { name: 'Add a list' }).click()
	await page.getByLabel('List', { exact: true }).selectOption({ label: 'E2E social' })
	await page.getByLabel('When').selectOption({ label: 'During E2E school' })
	await page.getByRole('button', { name: 'Create' }).click()
	await expect(page.getByRole('row').filter({ hasText: 'E2E kids' })).toBeVisible()

	await page.getByRole('link', { name: 'Clients', exact: true }).click()
	await page.getByRole('link', { name: 'New client' }).click()
	await page.getByLabel('Name').fill('E2E tablet')
	await page.getByLabel('Addresses').fill('192.168.77.23\nfd00::77')
	// A client ID: checked as typed, and shown as the device would use it.
	await page.getByLabel('Client IDs').fill('bad_id')
	await expect(page.getByText('Not a client ID: bad_id')).toBeVisible()
	await expect(page.getByRole('button', { name: 'Create' })).toBeDisabled()
	await page.getByLabel('Client IDs').fill('E2E-Tablet')
	const use = page.getByRole('note', { name: 'Using the client ID' })
	await expect(use).toContainText(`https://dns.example:${DOH_PORT}/dns-query/e2e-tablet`)
	await expect(use).toContainText(`e2e-tablet.dns.example (port ${DOT_PORT})`)
	await expect(use).toContainText(`quic://e2e-tablet.dns.example:${DOQ_PORT}`)
	await expect(use.getByText('Oblivious DoH target')).toBeVisible()
	await expect(use).toContainText('the device is anonymous')
	await page.getByLabel('Group').selectOption({ label: 'E2E kids' })
	await page.getByRole('button', { name: 'Create' }).click()
	const client = page.getByRole('row').filter({ hasText: 'E2E tablet' })
	await expect(client).toContainText('192.168.77.23, fd00::77')
	await expect(client).toContainText('e2e-tablet')
	await expect(client).toContainText('E2E kids')

	const groups = await apiCall(request, 'GET', '/api/v1/groups')
	const kids = groups.find((group: { spec: { name: string } }) => group.spec.name === 'E2E kids')
	expect(kids.spec.safe_search).toBe(true)
	expect(kids.spec.lists[0].list).toBe(list.id)
	expect(kids.spec.lists[0].schedule).toMatch(/^sc_/)

	// Clean up through the UI, the client first: a group in use stays.
	await client.getByRole('link', { name: 'E2E tablet' }).click()
	await page.getByRole('button', { name: 'Delete', exact: true }).click()
	await page.getByRole('button', { name: 'Delete this client' }).click()
	await expect(page.getByRole('row').filter({ hasText: 'E2E tablet' })).toHaveCount(0)
	await apiCall(request, 'DELETE', `/api/v1/groups/${kids.id}`)
	await apiCall(request, 'DELETE', `/api/v1/schedules/${kids.spec.lists[0].schedule}`)
	await apiCall(request, 'DELETE', `/api/v1/lists/${list.id}`)
})

test('saves settings, and the audit log shows the change', async ({ page }) => {
	await page.getByRole('link', { name: 'Settings', exact: true }).click()
	await page.getByLabel('Time to live of blocked answers, in seconds').fill('42')
	await page.getByRole('button', { name: 'Save' }).click()
	await expect(page.getByRole('status')).toContainText('Saved')

	await page.getByRole('link', { name: 'Audit log', exact: true }).click()
	const entry = page.getByRole('row').filter({ hasText: 'settings' }).first()
	await expect(entry).toContainText('UPDATE')
	await entry.getByRole('button', { name: 'Show change' }).click()
	await expect(page.locator('.change')).toContainText('"blocked_ttl": 42')

	await page.getByRole('link', { name: 'Settings', exact: true }).click()
	await page.getByLabel('Time to live of blocked answers, in seconds').fill('10')
	await page.getByRole('button', { name: 'Save' }).click()
	await expect(page.getByRole('status')).toContainText('Saved')
})

test('shows what Terraform manages read-only', async ({ page, request }) => {
	const rule = await apiCall(request, 'POST', '/api/v1/rules', {
		rule: '||e2e-terraform.example^',
		managed_by: 'terraform',
	})
	await page.getByRole('link', { name: 'Rules', exact: true }).click()
	const row = page.getByRole('row').filter({ hasText: '||e2e-terraform.example^' })
	await expect(row).toContainText('TERRAFORM')
	await expect(row.getByRole('checkbox')).toBeDisabled()
	await expect(row.getByRole('button', { name: 'Delete' })).toHaveCount(0)

	await row.getByRole('link', { name: '||e2e-terraform.example^' }).click()
	await expect(page.getByText('Terraform manages this rule')).toBeVisible()
	await expect(page.getByLabel('Rule')).toBeDisabled()
	await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0)
	await apiCall(request, 'DELETE', `/api/v1/rules/${rule.id}`)
})

test('refuses to overwrite a change made meanwhile', async ({ page, request }) => {
	const list = await apiCall(request, 'POST', '/api/v1/lists', {
		name: 'E2E shared',
		url: 'https://lists.example/e2e-shared.txt',
	})
	await page.goto(`/lists/${list.id}`)
	await page.getByLabel('Comment').fill('mine')
	// Someone else saves first.
	await apiCall(request, 'PUT', `/api/v1/lists/${list.id}`, { ...list.spec, comment: 'theirs' })

	await page.getByRole('button', { name: 'Save' }).click()
	await expect(page.getByRole('alert')).toBeVisible()
	await page.getByRole('button', { name: 'Load the current version' }).click()
	await expect(page.getByLabel('Comment')).toHaveValue('theirs')
	await apiCall(request, 'DELETE', `/api/v1/lists/${list.id}`)
})

test('serves the API reference under the strict policy', async ({ page }) => {
	const problems: string[] = []
	page.on('console', (message) => {
		if (message.type() === 'error') problems.push(message.text())
	})
	page.on('pageerror', (error) => problems.push(error.message))
	await page.goto('/api/docs')
	await expect(page).toHaveTitle('goethite API reference')
	// Scalar rendered the document: its sections and an operation.
	await expect(page.getByRole('link', { name: 'lists', exact: true })).toBeVisible()
	await expect(page.getByRole('heading', { name: 'Whether the API is up. Needs no token.' })).toBeVisible()
	// One theme, light, like the web UI.
	await expect(page.getByRole('button', { name: /dark mode/i })).toHaveCount(0)
	// More of it renders: a section, and the search dialog.
	await page.getByRole('link', { name: 'lists', exact: true }).click()
	await expect(page.getByRole('heading', { name: 'Creates a filter list.' })).toBeVisible()
	await page.getByRole('button', { name: /Open Search/ }).click()
	await expect(
		page.getByRole('dialog').getByRole('option', { name: /Creates a filter list/ }),
	).toBeVisible()
	expect(problems.filter((problem) => /Content Security Policy|Refused/i.test(problem))).toEqual([])
	expect(problems).toEqual([])
})

test('explains what keeps a schedule or a group from being deleted', async ({ page, request }) => {
	const schedule = await apiCall(request, 'POST', '/api/v1/schedules', {
		name: 'E2E evenings',
		windows: [{ days: ['mon'], start: '18:00', end: '22:00' }],
	})
	const list = await apiCall(request, 'POST', '/api/v1/lists', {
		name: 'E2E games',
		url: 'https://lists.example/e2e-games.txt',
	})
	const group = await apiCall(request, 'POST', '/api/v1/groups', {
		name: 'E2E teens',
		lists: [{ list: list.id, schedule: schedule.id }],
	})
	const client = await apiCall(request, 'POST', '/api/v1/clients', {
		name: 'E2E console',
		addresses: ['192.168.77.40'],
		group: group.id,
	})

	await page.goto(`/schedules/${schedule.id}`)
	await expect(page.getByText('Used by E2E teens')).toBeVisible()
	await expect(page.getByRole('button', { name: 'Delete', exact: true })).toHaveCount(0)

	await page.goto(`/groups/${group.id}`)
	await expect(page.getByText('1 client is in this group')).toBeVisible()
	await expect(page.getByRole('button', { name: 'Delete', exact: true })).toHaveCount(0)

	// A list in use goes: it is taken out of the group first.
	await page.goto(`/lists/${list.id}`)
	await expect(page.getByText('Used by E2E teens. Deleting it takes it out of them.')).toBeVisible()
	await page.getByRole('button', { name: 'Delete', exact: true }).click()
	await page.getByRole('button', { name: 'Delete this list' }).click()
	await expect(page).toHaveURL(/\/lists$/)
	const after = await apiCall(request, 'GET', `/api/v1/groups/${group.id}`)
	expect(after.spec.lists).toEqual([])

	await apiCall(request, 'DELETE', `/api/v1/clients/${client.id}`)
	await apiCall(request, 'DELETE', `/api/v1/groups/${group.id}`)
	await apiCall(request, 'DELETE', `/api/v1/schedules/${schedule.id}`)
})

/** Asks goethite for `name` over UDP, as a client would, and waits for the answer. */
async function ask(name: string): Promise<void> {
	const labels = name
		.split('.')
		.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]))
	const query = Buffer.concat([
		Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
		...labels,
		Buffer.from([0, 0, 1, 0, 1]),
	])
	const socket = createSocket('udp4')
	try {
		await new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error(`no answer for ${name}`)), 5_000)
			socket.once('message', () => {
				clearTimeout(timer)
				resolve()
			})
			socket.once('error', reject)
			socket.send(query, DNS_PORT, '127.0.0.1')
		})
	} finally {
		socket.close()
	}
}

test('blocks a service for a group, and the query log says which', async ({ page, request }) => {
	await page.getByRole('link', { name: 'Groups', exact: true }).click()
	await page.getByRole('link', { name: 'Default', exact: true }).click()
	const services = page.getByRole('group', { name: 'Blocked services' })
	await expect(services.getByText('No blocked services.')).toBeVisible()
	await services.getByLabel('Find a service').fill('stream')
	await expect(services.getByRole('heading', { name: 'Streaming' })).toBeVisible()
	await expect(services.getByLabel('TikTok')).toHaveCount(0)
	await services.getByLabel('Find a service').fill('tik')
	await services.getByLabel('TikTok').check()
	await expect(services.getByLabel('When TikTok is blocked')).toHaveValue('')
	await page.getByRole('button', { name: 'Save' }).click()
	const row = page.getByRole('row').filter({ hasText: 'Default' })
	await expect(row.getByRole('cell').nth(4)).toHaveText('1')
	const group = await apiCall(request, 'GET', '/api/v1/groups/default')
	expect(group.spec.blocked_services).toEqual([{ service: 'tiktok' }])

	await ask('www.tiktok.com')
	await page.getByRole('link', { name: 'Query log', exact: true }).click()
	await expect(page.getByRole('row').filter({ hasText: 'www.tiktok.com' }).first()).toContainText(
		'Blocked service TikTok · ||tiktok.com^',
	)

	await page.getByRole('link', { name: 'Groups', exact: true }).click()
	await page.getByRole('link', { name: 'Default', exact: true }).click()
	await page.getByRole('button', { name: 'Unblock TikTok' }).click()
	await page.getByRole('button', { name: 'Save' }).click()
	await expect(row.getByRole('cell').nth(4)).toHaveText('0')
	const after = await apiCall(request, 'GET', '/api/v1/groups/default')
	expect(after.spec.blocked_services).toEqual([])
})

test('the dashboard: a range, its queries, a bar and a quick rule', async ({ page, request }) => {
	const problems: string[] = []
	page.on('console', (message) => {
		if (message.type() === 'error') problems.push(message.text())
	})
	const block = await apiCall(request, 'POST', '/api/v1/rules', { rule: '||e2e-dash.example^' })
	for (const name of ['e2e-dash.example', 'e2e-dash.example', 'goethite.test']) {
		await ask(name)
	}

	// The statistics follow within moments.
	const topBlocked = page.getByRole('region', { name: 'Top blocked' })
	await expect(async () => {
		await page.goto('/')
		await expect(topBlocked.getByRole('link', { name: 'e2e-dash.example' })).toBeVisible({ timeout: 1_000 })
	}).toPass({ timeout: 20_000 })

	// A range is part of the address; the tabs stay where they are.
	await page.getByRole('navigation', { name: 'Time range' }).getByRole('link', { name: '7 days' }).click()
	await expect(page).toHaveURL(/range=7d/)
	await expect(page.getByText('Queries, 7 days')).toBeVisible()
	await expect(page.getByRole('region', { name: 'Queries per 6 hours' })).toBeVisible()
	await expect(page.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('aria-current', 'page')

	// A tile opens its queries, over the same range.
	await page.getByRole('link', { name: /^Blocked/ }).click()
	await expect(page).toHaveURL(/\/querylog\?.*outcome=blocked/)
	const filters = page.getByRole('list', { name: 'Filters' })
	await expect(filters).toContainText('Since')
	await expect(page.getByRole('row').filter({ hasText: 'e2e-dash.example' }).first()).toBeVisible()
	await page.getByRole('button', { name: /Remove the filter Since/ }).click()
	await expect(filters).toHaveCount(0)
	await expect(page.getByLabel('Answer')).toHaveValue('blocked')

	// A name in a top list opens its queries too.
	await page.goto('/')
	await topBlocked.getByRole('link', { name: 'e2e-dash.example' }).click()
	await expect(page).toHaveURL(/name=e2e-dash\.example/)
	await expect(page.getByLabel('Name contains')).toHaveValue('e2e-dash.example')

	// A bar shows its counts, and opens its time window.
	await page.goto('/')
	const chart = page.getByRole('img', { name: 'Queries over time' })
	// Near its top: the blocked part sits in front lower down.
	const bar = chart.locator('rect[data-ts-key^="queries:"]').last()
	await bar.hover({ position: { x: 8, y: 2 } })
	await expect(page.locator('.chart-tooltip')).toContainText('Queries')
	await bar.click({ position: { x: 8, y: 2 } })
	await expect(page).toHaveURL(/\/querylog\?.*since=.*until=/)
	await expect(filters).toContainText('until')
	await expect(page.getByRole('row').filter({ hasText: 'e2e-dash.example' }).first()).toBeVisible()

	// A quick rule, after asking.
	await page.goto('/')
	await topBlocked
		.getByRole('row')
		.filter({ has: page.getByRole('link', { name: 'e2e-dash.example' }) })
		.getByRole('button', { name: 'Allow', exact: true })
		.click()
	const question = topBlocked.getByRole('group', { name: 'Allow e2e-dash.example?' })
	await expect(question).toContainText('@@||e2e-dash.example^')
	await question.getByRole('button', { name: 'Allow e2e-dash.example' }).click()
	await expect(topBlocked.getByRole('status')).toContainText('@@||e2e-dash.example^')
	const rules: { id: string; spec: { rule: string; enabled?: boolean } }[] = await apiCall(
		request,
		'GET',
		'/api/v1/rules',
	)
	const allow = rules.find((rule) => rule.spec.rule === '@@||e2e-dash.example^')
	expect(allow?.spec.enabled).toBe(true)

	await apiCall(request, 'DELETE', `/api/v1/rules/${allow?.id}`)
	await apiCall(request, 'DELETE', `/api/v1/rules/${block.id}`)
	// The chart ran under the strict Content Security Policy throughout.
	expect(problems).toEqual([])
})

/** Takes `list` out of the default group and deletes it, behind the UI's back. */
async function removeList(request: APIRequestContext, list: string) {
	const group = await apiCall(request, 'GET', '/api/v1/groups/default')
	await apiCall(request, 'PUT', '/api/v1/groups/default', {
		...group.spec,
		lists: group.spec.lists.filter((entry: { list: string }) => entry.list !== list),
	})
	await apiCall(request, 'DELETE', `/api/v1/lists/${list}`)
}

/** Deletes every list, behind the UI's back, after taking them out of the default group. */
async function removeAllLists(request: APIRequestContext) {
	const lists: { id: string }[] = await apiCall(request, 'GET', '/api/v1/lists')
	for (const list of lists) await removeList(request, list.id)
}

/** The default group's lists, by URL, and whether each is on. */
async function defaultGroupLists(request: APIRequestContext): Promise<Map<string, boolean>> {
	const lists: { id: string; spec: { url?: string; enabled?: boolean } }[] = await apiCall(
		request,
		'GET',
		'/api/v1/lists',
	)
	const group = await apiCall(request, 'GET', '/api/v1/groups/default')
	const used = new Set(group.spec.lists.map((entry: { list: string }) => entry.list))
	return new Map(
		lists.filter((list) => used.has(list.id)).map((list) => [list.spec.url ?? '', list.spec.enabled !== false]),
	)
}

const HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/'

test('recommended lists by category: add, overlap, legacy', async ({ page, request }) => {
	await page.getByRole('link', { name: 'Lists', exact: true }).click()
	const recommended = page.getByRole('region', { name: 'Recommended lists' })
	for (const heading of ['Presets', 'Base list', 'Security', 'Optional', 'Bypass prevention', 'Device trackers', 'Family', 'Hardening']) {
		await expect(recommended.getByRole('heading', { name: heading, exact: true })).toBeVisible()
	}
	const normal = recommended.getByRole('row').filter({ hasText: 'HaGeZi Multi Normal' })
	await expect(normal).toContainText('★ RECOMMENDED')
	await expect(normal).toContainText('DEFAULT')
	await expect(recommended.getByRole('row').filter({ hasText: 'HaGeZi Multi Ultimate' })).toContainText('STRICT')

	// Legacy lists are tucked away.
	await expect(recommended.getByRole('row').filter({ hasText: 'AdAway' })).toBeHidden()
	await recommended.getByText('Legacy lists').click()
	await expect(recommended.getByRole('row').filter({ hasText: 'AdAway' })).toBeVisible()

	await recommended.getByRole('button', { name: 'Add: OISD Small' }).click()
	await expect(recommended.getByRole('row').filter({ hasText: 'OISD Small' })).toContainText('ADDED')
	await expect(page.getByRole('row').filter({ hasText: 'https://small.oisd.nl/' })).toBeVisible()
	expect((await defaultGroupLists(request)).get('https://small.oisd.nl/')).toBe(true)

	// A second base list: they overlap.
	await expect(recommended.getByRole('status').filter({ hasText: 'Overlap' })).toHaveCount(0)
	await recommended.getByRole('button', { name: 'Add: HaGeZi Multi Light' }).click()
	await expect(recommended.getByRole('status').filter({ hasText: 'Overlap' })).toContainText(
		'HaGeZi Multi Light and OISD Small',
	)
	await removeAllLists(request)
})

test('presets: preview, apply, swap; switching instead of stacking', async ({ page, request }) => {
	await page.getByRole('link', { name: 'Lists', exact: true }).click()
	const recommended = page.getByRole('region', { name: 'Recommended lists' })
	const balanced = recommended.getByRole('article', { name: 'Preset Balanced' })
	await expect(balanced).toContainText('DEFAULT')
	await balanced.getByRole('button', { name: 'Use for a group' }).click()
	const preview = recommended.getByRole('group', { name: 'Use Balanced' })
	await expect(preview).toContainText(
		'New, downloaded at once: HaGeZi Multi Normal, HaGeZi Threat Intelligence Feeds Mini, HaGeZi Fake',
	)
	await preview.getByRole('button', { name: 'Use Balanced' }).click()
	await expect(preview).toBeHidden()
	let used = await defaultGroupLists(request)
	expect([...used.keys()].sort()).toEqual([`${HAGEZI}fake.txt`, `${HAGEZI}multi.txt`, `${HAGEZI}tif.mini.txt`])

	// Another preset: what it does not have leaves, and is turned off.
	await recommended.getByRole('article', { name: "Preset Don't break anything" }).getByRole('button', { name: 'Use for a group' }).click()
	const minimal = recommended.getByRole('group', { name: "Use Don't break anything" })
	await expect(minimal).toContainText('no longer uses HaGeZi Multi Normal, HaGeZi Fake')
	await expect(minimal).toContainText('Turned off, no group uses them: HaGeZi Multi Normal, HaGeZi Fake')
	await minimal.getByRole('button', { name: "Use Don't break anything" }).click()
	await expect(minimal).toBeHidden()
	used = await defaultGroupLists(request)
	expect([...used.keys()].sort()).toEqual([`${HAGEZI}light.txt`, `${HAGEZI}tif.mini.txt`])

	// TIF replaces TIF Mini: switch, never stack.
	const tif = recommended.getByRole('row').filter({ hasText: 'HaGeZi Threat Intelligence Feeds' }).filter({ hasText: 'MAX SECURITY' })
	await tif.getByRole('button', { name: /^Switch from HaGeZi Threat Intelligence Feeds Mini/ }).click()
	const swap = recommended.getByRole('group', { name: 'Switch to HaGeZi Threat Intelligence Feeds' })
	await expect(swap).toContainText('Turned off, no group uses them: HaGeZi Threat Intelligence Feeds Mini')
	await swap.getByRole('button', { name: 'Switch to HaGeZi Threat Intelligence Feeds' }).click()
	await expect(swap).toBeHidden()
	used = await defaultGroupLists(request)
	expect([...used.keys()].sort()).toEqual([`${HAGEZI}light.txt`, `${HAGEZI}tif.txt`])
	const lists: { spec: { url?: string; enabled?: boolean } }[] = await apiCall(request, 'GET', '/api/v1/lists')
	expect(lists.find((list) => list.spec.url === `${HAGEZI}tif.mini.txt`)?.spec.enabled).toBe(false)
	await removeAllLists(request)
})

test('says when the FilterLists directory is turned off', async ({ page }) => {
	await page.goto('/lists/find')
	await expect(page.getByRole('alert')).toContainText('[filter] directory')
})

test('finds a list in the FilterLists directory, and adds it after checking', async ({ page, request }) => {
	// The node's answers, as if it had asked FilterLists.
	await page.route('**/api/v1/lists/directory', (route) =>
		route.fulfill({
			json: {
				fetched_at: '2026-10-08T12:00:00Z',
				lists: [
					{ id: 77, name: 'E2E Trackers', description: 'Tracking domains.', tags: ['privacy'], syntaxes: ['Domains'], license: 'MIT' },
					{ id: 78, name: 'E2E Ads', description: 'Ad servers.', tags: ['ads'], syntaxes: ['Hosts (localhost IPv4)'] },
					{ id: 79, name: 'E2E Two parts', description: 'Big.', tags: ['ads'], syntaxes: ['Domains'] },
				],
			},
		}),
	)
	await page.route('**/api/v1/lists/directory/77', (route) =>
		route.fulfill({
			json: {
				id: 77,
				name: 'E2E Trackers',
				description: 'Tracking domains.',
				tags: ['privacy'],
				syntaxes: ['Domains'],
				license: 'MIT',
				homepage: 'https://lists.example',
				urls: [
					{ url: 'https://lists.example/trackers.txt', segment: 1, mirror: false },
					{ url: 'https://mirror.example/trackers.txt', segment: 1, mirror: true },
				],
				usable: true,
			},
		}),
	)
	await page.goto('/lists/find')
	await expect(page.getByRole('status')).toContainText('3 of 3 lists')
	await page.getByLabel('Topic').selectOption('privacy')
	await expect(page.getByRole('status')).toContainText('1 of 3 lists')
	await page.getByLabel('Topic').selectOption('')
	await page.getByLabel('Name or description').fill('ad servers')
	await expect(page.getByRole('status')).toContainText('1 of 3 lists')
	await page.getByLabel('Name or description').fill('')

	await page.getByRole('button', { name: 'Show E2E Trackers' }).click()
	await expect(page.getByText('(mirror)')).toBeVisible()
	await page.getByRole('link', { name: 'Add https://lists.example/trackers.txt' }).click()

	// The usual form, filled in, to check before saving.
	await expect(page.getByLabel('Name')).toHaveValue('E2E Trackers')
	await expect(page.getByLabel('URL')).toHaveValue('https://lists.example/trackers.txt')
	await expect(page.getByLabel('Comment')).toHaveValue('From the FilterLists directory (list 77).')
	await page.getByRole('button', { name: 'Create' }).click()
	await expect(page.getByRole('row').filter({ hasText: 'https://lists.example/trackers.txt' })).toBeVisible()

	const lists: { id: string; spec: { url?: string } }[] = await apiCall(request, 'GET', '/api/v1/lists')
	const added = lists.find((list) => list.spec.url === 'https://lists.example/trackers.txt')
	expect(added).toBeDefined()
	await removeList(request, added?.id ?? '')
})
