// Starts a goethite for the end-to-end tests: a fresh store, a known admin
// token, the API on 127.0.0.1:18153 serving this web UI, DNS over TLS, HTTPS
// and QUIC with a certificate goethite makes itself, and a services catalog. GOETHITE_BIN names the
// binary (default: the workspace's debug build, which reads web/dist from
// disk). Playwright stops it when the tests are done.
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { API_PORT, DNS_PORT, DOH_PORT, DOQ_PORT, DOT_PORT, PASSWORD, TOKEN, USER } from './settings.mjs'

const binary = process.env.GOETHITE_BIN ?? resolve(import.meta.dirname, '../../target/debug/goethite')
const dir = mkdtempSync(join(tmpdir(), 'goethite-e2e-'))
const hash = createHash('sha256').update(TOKEN).digest('hex')
const config = join(dir, 'goethite.toml')
// A services catalog in the format of AdGuard's, read from a file instead of downloaded.
const services = join(dir, 'services.json')
writeFileSync(
	services,
	JSON.stringify({
		groups: [{ id: 'social_network' }, { id: 'streaming' }],
		blocked_services: [
			{ id: 'tiktok', name: 'TikTok', group: 'social_network', rules: ['||tiktok.com^', '||tiktokv.com^'] },
			{ id: 'youtube', name: 'YouTube', group: 'streaming', rules: ['||youtube.com^', '||youtu.be^'] },
			{ id: 'twitch', name: 'Twitch', group: 'streaming', rules: ['||twitch.tv^'] },
		],
	}),
)
// Any certificate does: the tests read what the UI says, not the handshake.
for (const args of [['init'], ['cert', 'dns']]) {
	execFileSync(binary, ['cluster', ...args, '--dir', dir], { stdio: 'ignore' })
}
writeFileSync(
	config,
	`[server]
listen = "127.0.0.1:${DNS_PORT}"

[server.tls]
cert = "${join(dir, 'dns.crt')}"
key = "${join(dir, 'dns.key')}"
server_name = "dns.example"
dot = "127.0.0.1:${DOT_PORT}"
doh = "127.0.0.1:${DOH_PORT}"
doq = "127.0.0.1:${DOQ_PORT}"
odoh = true

[[upstream]]
address = "192.0.2.1"

[filter]
# Offline: no default list to download, no FilterLists directory to ask, and
# the services catalog from a file.
default_lists = false
directory = false
services_file = "${services}"

[api]
listen = "127.0.0.1:${API_PORT}"
token_sha256 = "${hash}"
docs = true

[store]
path = "${join(dir, 'goethite.redb')}"
`,
)

// The admin the tests sign in as. The store is created here, before the
// server starts, because a running goethite holds its store file locked.
const passwordFile = join(dir, 'password.txt')
writeFileSync(passwordFile, PASSWORD)
execFileSync(binary, ['user', 'add', USER, '--password-file', passwordFile, '--config', config], {
	stdio: 'inherit',
})

const child = spawn(binary, ['run', '--config', config], { stdio: 'inherit' })
const stop = () => {
	child.kill('SIGTERM')
}
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
child.on('exit', (code) => {
	rmSync(dir, { recursive: true, force: true })
	process.exit(code ?? 0)
})
