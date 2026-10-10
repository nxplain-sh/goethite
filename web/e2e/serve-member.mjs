// Starts a second goethite for the cluster page: dns2, a member of a cluster
// that has not started. Its config file lists dns1, where nothing answers,
// and it does not bootstrap, so it waits to be added until a test starts a
// cluster on it. The API on 127.0.0.1:18158 with the same admin token.
// GOETHITE_BIN names the binary, as for e2e/serve.mjs.
import { execFileSync, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { ABSENT_PORT, MEMBER_API_PORT, MEMBER_CLUSTER_PORT, MEMBER_DNS_PORT, TOKEN } from './settings.mjs'

const binary = process.env.GOETHITE_BIN ?? resolve(import.meta.dirname, '../../target/debug/goethite')
const dir = mkdtempSync(join(tmpdir(), 'goethite-e2e-member-'))
const hash = createHash('sha256').update(TOKEN).digest('hex')
const config = join(dir, 'goethite.toml')
for (const args of [['init'], ['cert', 'dns2']]) {
	execFileSync(binary, ['cluster', ...args, '--dir', dir], { stdio: 'ignore' })
}
writeFileSync(
	config,
	`[server]
listen = "127.0.0.1:${MEMBER_DNS_PORT}"

[[upstream]]
address = "192.0.2.1"

[filter]
# Offline: nothing to download.
default_lists = false
directory = false
services = false

[api]
listen = "127.0.0.1:${MEMBER_API_PORT}"
token_sha256 = "${hash}"

[store]
path = "${join(dir, 'goethite.redb')}"

[cluster]
node = "dns2"
listen = "127.0.0.1:${MEMBER_CLUSTER_PORT}"
ca = "${join(dir, 'ca.crt')}"
cert = "${join(dir, 'dns2.crt')}"
key = "${join(dir, 'dns2.key')}"

[[cluster.member]]
node = "dns1"
address = "127.0.0.1:${ABSENT_PORT}"
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
