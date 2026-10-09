// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Deployed to GitHub Pages as a project site: https://nxplain-sh.github.io/goethite/
// If a custom domain is configured later, set `site` to it and drop `base`.
export default defineConfig({
	site: 'https://nxplain-sh.github.io',
	base: '/goethite',
	integrations: [
		starlight({
			title: 'goethite',
			description:
				'A self-hosted, clustered, security-hardened DNS filtering resolver written in Rust.',
			favicon: '/favicon.svg',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/nxplain-sh/goethite' },
			],
			editLink: {
				baseUrl: 'https://github.com/nxplain-sh/goethite/edit/main/site/',
			},
			sidebar: [
				{ label: 'Quick start', slug: 'quick-start' },
				{ label: 'Install on Linux', slug: 'install' },
				{ label: 'Verifying releases', slug: 'verify' },
				{ label: 'Configuration', slug: 'configuration' },
				{ label: 'Filtering', slug: 'filtering' },
				{ label: 'Clients and groups', slug: 'groups' },
				{ label: 'Local records', slug: 'local-records' },
				{ label: 'DNS leak test', slug: 'leak-test' },
				{ label: 'Encrypted DNS', slug: 'encrypted-dns' },
				{ label: 'Recursion', slug: 'recursion' },
				{ label: 'High availability', slug: 'ha' },
				{ label: 'REST API', slug: 'api' },
				{ label: 'Web UI', slug: 'web-ui' },
				{ label: 'Terminal UI', slug: 'tui' },
				{ label: 'Terraform', slug: 'terraform' },
				{ label: 'Security settings', slug: 'security' },
				{ label: 'API reference', slug: 'api-reference' },
				{ label: 'Changelog', slug: 'changelog' },
			],
			// Fonts are bundled from npm and served from this site: no font CDN at runtime.
			customCss: [
				'@fontsource-variable/space-grotesk',
				'@fontsource-variable/jetbrains-mono',
				'./src/styles/theme.css',
			],
			expressiveCode: {
				// Starlight already sets radius 0 and the site fonts; add the thick ink frame.
				// (The hard shadow lives in theme.css: Starlight's per-theme EC settings override
				// a global `frames.frameBoxShadowCssValue`.)
				styleOverrides: {
					borderWidth: '3px',
					// `--sl-color-white` is the ink color in both themes.
					borderColor: 'var(--sl-color-white)',
				},
			},
		}),
	],
});
