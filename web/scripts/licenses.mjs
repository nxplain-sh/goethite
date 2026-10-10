// Prints the licence notices of the npm packages that ship inside goethite's
// binary: the web UI's dependencies and the API reference, both bundled by
// `npm run build`. `cargo xtask dist` puts them in THIRD-PARTY-LICENSES.txt
// with the Rust crates' notices.
//
// It reads package-lock.json for the packages that are not development-only,
// and each one's licence files from node_modules, so it runs after `npm ci`.
// The output is sorted, so the same lockfile gives the same bytes.
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const root = join(import.meta.dirname, '..')
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'))
const LICENCE_FILE = /^(licen[cs]e|copying|notice)([.-].*)?$/i
const RULE = '-'.repeat(78)
// A code-point order, the same whatever the locale.
const byPath = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)

const notices = []
for (const [path, entry] of Object.entries(lock.packages).sort(byPath)) {
	if (!path.startsWith('node_modules/') || entry.dev || entry.devOptional) continue
	const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
	const dir = join(root, path)
	const files = readdirSync(dir)
		.filter((file) => LICENCE_FILE.test(file))
		.sort()
	const texts = files.map((file) => readFileSync(join(dir, file), 'utf8').trimEnd())
	if (texts.length === 0) {
		// The notice then is the licence and the author the package names.
		const { author } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
		const by = typeof author === 'string' ? author : (author?.name ?? 'its authors')
		texts.push(`(No licence file in the package.) Copyright ${by}, under the ${entry.license} licence.`)
	}
	notices.push(
		[RULE, `${name} ${entry.version}, licence: ${entry.license ?? 'not stated'}`, '', ...texts].join('\n'),
	)
}
process.stdout.write(`${notices.join('\n\n')}\n`)
