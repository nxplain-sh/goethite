import { describe, expect, it } from 'vite-plus/test'

import { isLoopback } from './DocsLinks'

describe('the API reference link', () => {
	it('asks this node only from this machine', () => {
		for (const host of ['localhost', 'goethite.localhost', '127.0.0.1', '127.1.2.3', '[::1]']) {
			expect(isLoopback(host), host).toBe(true)
		}
		for (const host of ['192.168.1.2', 'dns.example.lan', '127.0.0.1.example', '[::2]', '']) {
			expect(isLoopback(host), host).toBe(false)
		}
	})
})
