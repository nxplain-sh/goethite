// Fails the build when the web UI grows past its budget. The UI ships inside
// the goethite binary and loads over the LAN on first visit, so its size is
// a feature: raise a limit only on purpose.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const KiB = 1024
const limits = {
	js: 200 * KiB, // gzipped
	css: 16 * KiB, // gzipped
	total: 1536 * KiB, // everything in dist/, uncompressed, as embedded
}

function files(dir) {
	return readdirSync(dir).flatMap((name) => {
		const path = join(dir, name)
		return statSync(path).isDirectory() ? files(path) : [path]
	})
}

const all = files('dist')
const gzipped = (ext) =>
	all.filter((path) => path.endsWith(ext)).reduce((sum, path) => sum + gzipSync(readFileSync(path)).length, 0)
const sizes = {
	js: gzipped('.js'),
	css: gzipped('.css'),
	total: all.reduce((sum, path) => sum + statSync(path).size, 0),
}

let over = false
for (const [name, size] of Object.entries(sizes)) {
	const limit = limits[name]
	const line = `${name.padEnd(6)} ${(size / KiB).toFixed(1).padStart(7)} KiB of ${limit / KiB} KiB`
	if (size > limit) {
		over = true
		console.error(`${line}  OVER BUDGET`)
	} else {
		console.log(line)
	}
}
process.exit(over ? 1 : 0)
