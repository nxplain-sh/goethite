// Serves the built site (dist/client) the way GitHub Pages does: under the
// /goethite/ base, a directory's index.html for its path, a redirect to the
// slash for a directory asked for without one, and 404.html with status 404
// for anything else. `npm run preview`, after `npm run build`.
import { createReadStream, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize } from 'node:path'

const base = '/goethite/'
const root = join(import.meta.dirname, '..', 'dist', 'client')
const port = Number(process.env.PORT ?? 4321)
const types = {
	'.html': 'text/html; charset=utf-8',
	'.js': 'text/javascript; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.json': 'application/json',
	'.svg': 'image/svg+xml',
	'.woff2': 'font/woff2',
	'.xml': 'application/xml',
	'.wasm': 'application/wasm',
}

function kind(path) {
	try {
		return statSync(path).isDirectory() ? 'directory' : 'file'
	} catch {
		return null
	}
}

function send(response, status, path) {
	response.writeHead(status, { 'content-type': types[extname(path)] ?? 'application/octet-stream' })
	createReadStream(path).pipe(response)
}

createServer((request, response) => {
	const { pathname } = new URL(request.url ?? '/', 'http://localhost')
	if (!pathname.startsWith(base)) {
		response.writeHead(302, { location: base }).end()
		return
	}
	const path = join(root, normalize(decodeURIComponent(pathname.slice(base.length))))
	if (!path.startsWith(root)) {
		response.writeHead(400).end()
		return
	}
	const found = kind(path)
	if (found === 'file') {
		send(response, 200, path)
	} else if (found === 'directory' && !pathname.endsWith('/')) {
		response.writeHead(301, { location: `${pathname}/` }).end()
	} else if (found === 'directory' && kind(join(path, 'index.html')) === 'file') {
		send(response, 200, join(path, 'index.html'))
	} else {
		send(response, 404, join(root, '404.html'))
	}
}).listen(port, '127.0.0.1', () => {
	console.log(`http://127.0.0.1:${port}${base}`)
})
