// Builds the API reference that goethite serves at /api/docs when
// `[api] docs` is on: Scalar's standalone bundle, gzipped, in dist-docs/.
// It is kept apart from dist/ and its size budget: the web UI never loads
// it, and goethite serves it only to loopback clients that ask for it.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

// The package exports no path to its standalone build, so it is read where
// npm installs it.
const bundle = readFileSync(
	join(import.meta.dirname, '../node_modules/@scalar/api-reference/dist/browser/standalone.js'),
)
mkdirSync('dist-docs', { recursive: true })
const gzipped = gzipSync(bundle, { level: 9 })
writeFileSync('dist-docs/scalar.js.gz', gzipped)
console.log(
	`API reference: ${(bundle.length / 1024).toFixed(0)} KiB, ` +
		`${(gzipped.length / 1024).toFixed(0)} KiB gzipped, in dist-docs/`,
)
