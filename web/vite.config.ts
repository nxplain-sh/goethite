import { defineConfig } from 'vite'

// The build is embedded into the goethite binary and served under a strict
// Content Security Policy (script-src 'self', no inline code, no data: fonts),
// so nothing is inlined into the HTML and no asset becomes a data: URL.
export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  build: {
    target: 'es2022',
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    rolldownOptions: {
      // React Server Components' "use client" means nothing in a client-only app.
      onwarn(warning, warn) {
        if (warning.code !== 'MODULE_LEVEL_DIRECTIVE') {
          warn(warning)
        }
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // `npm run dev` talks to a goethite node running on this machine. The
    // proxy keeps the browser's Host header, so the API's origin check sees
    // a same-origin request.
    proxy: {
      '/api': 'http://127.0.0.1:8053',
    },
  },
})
