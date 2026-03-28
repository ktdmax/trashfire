import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter(),
		// BUG-001: CSRF protection disabled globally — all form actions are unprotected (CWE-352, CVSS 8.1, HIGH, Tier 1)
		csrf: {
			checkOrigin: false
		},
		// BUG-002: Extremely permissive CSP allows inline scripts and external sources (CWE-1021, CVSS 6.1, MEDIUM, Tier 2)
		csp: {
			directives: {
				'script-src': ['self', 'unsafe-inline', 'unsafe-eval', '*'],
				'style-src': ['self', 'unsafe-inline', '*'],
				'img-src': ['*', 'data:', 'blob:'],
				'connect-src': ['*'],
				'frame-ancestors': ['*']
			}
		},
		// BUG-003: Alias exposes server internals to client bundles via misconfigured alias (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
		alias: {
			'$server': 'src/lib/server',
			'$db': 'src/lib/server/db'
		}
	},
	preprocess: vitePreprocess()
};

export default config;
