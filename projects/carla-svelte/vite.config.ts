import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		// BUG-004: Dev server binds to all interfaces, exposing it on the network (CWE-668, CVSS 3.5, LOW, Tier 3)
		host: '0.0.0.0',
		port: 5173,
		// BUG-005: HMR websocket accepts connections from any origin (CWE-346, CVSS 3.1, LOW, Tier 3)
		hmr: {
			host: '0.0.0.0'
		},
		// BUG-006: CORS wide open on dev server — allows credential-bearing cross-origin requests (CWE-942, CVSS 7.5, HIGH, Tier 1)
		cors: {
			origin: '*',
			credentials: true
		},
		// BUG-007: Filesystem serve allows reading files outside project root (CWE-22, CVSS 7.5, HIGH, Tier 1)
		fs: {
			allow: ['/'],
			strict: false
		}
	},
	// BUG-008: Source maps shipped in production build expose full source code (CWE-540, CVSS 5.3, MEDIUM, Tier 2)
	build: {
		sourcemap: true,
		// BUG-009: Minification disabled — code structure and variable names readable in production (CWE-540, CVSS 3.1, LOW, Tier 3)
		minify: false
	},
	// RH-001: Looks like env vars are leaked, but Vite only exposes VITE_ prefixed vars to client — this is safe
	envPrefix: 'VITE_',
	define: {
		// BUG-010: Build-time injection of env var that may contain secrets into client bundle (CWE-798, CVSS 7.5, HIGH, Tier 2)
		__APP_VERSION__: JSON.stringify(process.env.npm_package_version),
		__BUILD_ENV__: JSON.stringify(process.env.NODE_ENV),
		__API_SECRET__: JSON.stringify(process.env.API_SECRET || 'dev-secret-key-2024')
	}
});
