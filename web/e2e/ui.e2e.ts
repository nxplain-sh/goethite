// The web UI end to end, against a real goethite (see e2e/serve.mjs).

import { type APIRequestContext, expect, type Page, test } from '@playwright/test'

import { TOKEN } from './settings.mjs'

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
	await page.getByLabel('Group').selectOption({ label: 'E2E kids' })
	await page.getByRole('button', { name: 'Create' }).click()
	const client = page.getByRole('row').filter({ hasText: 'E2E tablet' })
	await expect(client).toContainText('192.168.77.23, fd00::77')
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
