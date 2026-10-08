// Starts a goethite for the end-to-end tests: a fresh store, a known admin
// token, the API on 127.0.0.1:18153 serving this web UI, and DNS over TLS
// and HTTPS with a certificate goethite makes itself. GOETHITE_BIN names the
// binary (default: the workspace's debug build, which reads web/dist from
// disk). Playwright stops it when the tests are done.
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { API_PORT, DNS_PORT, DOH_PORT, DOT_PORT, TOKEN } from './settings.mjs'

const binary = process.env.GOETHITE_BIN ?? resolve(import.meta.dirname, '../../target/debug/goethite')
const dir = mkdtempSync(join(tmpdir(), 'goethite-e2e-'))
const hash = createHash('sha256').update(TOKEN).digest('hex')
const config = join(dir, 'goethite.toml')
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

[[upstream]]
address = "192.0.2.1"

[api]
listen = "127.0.0.1:${API_PORT}"
token_sha256 = "${hash}"
docs = true

[store]
path = "${join(dir, 'goethite.redb')}"
`,
)

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
