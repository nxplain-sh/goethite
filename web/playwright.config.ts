import { defineConfig, devices } from '@playwright/test'

import { API_PORT } from './e2e/settings.mjs'

// End-to-end tests: Chromium against a real goethite (e2e/serve.mjs) that
// serves the built web UI. Build it first: `npm run build`. One goethite and
// one worker, since the tests share its configuration.
export default defineConfig({
	testDir: 'e2e',
	testMatch: '*.e2e.ts',
	fullyParallel: false,
	workers: 1,
	forbidOnly: true,
	retries: 0,
	reporter: [['list']],
	use: {
		baseURL: `http://127.0.0.1:${API_PORT}`,
		trace: 'retain-on-failure',
	},
	projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
	webServer: {
		command: 'node e2e/serve.mjs',
		url: `http://127.0.0.1:${API_PORT}/api/v1/health`,
		reuseExistingServer: false,
		timeout: 60_000,
		stdout: 'ignore',
		stderr: 'pipe',
	},
})
