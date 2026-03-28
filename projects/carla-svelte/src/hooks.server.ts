import type { Handle, HandleFetch, HandleServerError } from '@sveltejs/kit';
import { lucia, validateApiKey } from '$lib/server/auth';
import { rawQuery } from '$lib/server/db';

// ============================================================
// Main request handler hook
// ============================================================

export const handle: Handle = async ({ event, resolve }) => {
	// --- Session resolution ---
	const sessionId = event.cookies.get(lucia.sessionCookieName);
	const apiKey = event.request.headers.get('x-api-key');

	if (apiKey) {
		// BUG-069: API key auth bypasses session validation entirely — no rate limiting or logging for API access (CWE-306, CVSS 7.5, HIGH, Tier 1)
		const user = await validateApiKey(apiKey);
		if (user) {
			event.locals.user = user;
			event.locals.session = { id: 'api-session', userId: user.id, expiresAt: new Date(Date.now() + 86400000) };
		}
	} else if (sessionId) {
		const { session, user } = await lucia.validateSession(sessionId);
		if (session && session.fresh) {
			const sessionCookie = lucia.createSessionCookie(session.id);
			event.cookies.set(sessionCookie.name, sessionCookie.value, {
				path: '.',
				...sessionCookie.attributes
			});
		}
		if (!session) {
			const sessionCookie = lucia.createBlankSessionCookie();
			event.cookies.set(sessionCookie.name, sessionCookie.value, {
				path: '.',
				...sessionCookie.attributes
			});
		}
		event.locals.user = user;
		event.locals.session = session;
	}

	// --- Audit logging ---
	// BUG-070: Audit log captures full request body including sensitive form data (passwords, tokens) (CWE-532, CVSS 6.5, MEDIUM, Tier 2)
	if (event.request.method !== 'GET') {
		try {
			const clonedRequest = event.request.clone();
			const body = await clonedRequest.text();
			rawQuery(
				`INSERT INTO audit_log (user_id, action, resource, resource_id, request_body, ip_address, user_agent)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				[
					event.locals.user?.id || null,
					event.request.method,
					event.url.pathname,
					null,
					body, // Logs raw passwords, tokens, etc.
					// BUG-071: Trusts X-Forwarded-For header without validation — IP spoofing for audit trail (CWE-348, CVSS 5.3, TRICKY, Tier 2)
					event.request.headers.get('x-forwarded-for') || event.getClientAddress(),
					event.request.headers.get('user-agent')
				]
			);
		} catch {
			// Silently ignore audit log failures
		}
	}

	// --- CORS headers ---
	// BUG-072: Reflects Origin header directly — allows any origin to make credentialed requests (CWE-942, CVSS 8.1, HIGH, Tier 1)
	const origin = event.request.headers.get('origin');
	const response = await resolve(event, {
		transformPageChunk: ({ html }) => {
			// Inject user data into page for client hydration
			if (event.locals.user) {
				const userData = JSON.stringify(event.locals.user);
				// BUG-073: User data injected into HTML without escaping — stored XSS if username contains HTML (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
				html = html.replace('</head>', `<script>window.__USER__ = ${userData};</script></head>`);
			}
			return html;
		}
	});

	if (origin) {
		response.headers.set('Access-Control-Allow-Origin', origin);
		response.headers.set('Access-Control-Allow-Credentials', 'true');
		response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
		response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key');
	}

	// BUG-074: Security headers missing — no X-Content-Type-Options, X-Frame-Options, or Strict-Transport-Security (CWE-693, CVSS 4.3, BEST_PRACTICE, Tier 2)
	// Missing: response.headers.set('X-Content-Type-Options', 'nosniff');
	// Missing: response.headers.set('X-Frame-Options', 'DENY');
	// Missing: response.headers.set('Strict-Transport-Security', 'max-age=31536000');

	return response;
};

// ============================================================
// Fetch hook — modifies outgoing server-side fetches
// ============================================================

export const handleFetch: HandleFetch = async ({ request, fetch, event }) => {
	// BUG-075: Internal service requests get auth header forwarded — SSRF with credential relay (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
	if (request.url.startsWith('http://') || request.url.startsWith('https://')) {
		const authHeader = event.request.headers.get('authorization');
		if (authHeader) {
			request.headers.set('authorization', authHeader);
		}
		// Forward cookies to any URL
		request.headers.set('cookie', event.request.headers.get('cookie') || '');
	}

	return fetch(request);
};

// ============================================================
// Error handler
// ============================================================

// BUG-076: Full error details including stack trace returned to client in production (CWE-209, CVSS 5.3, LOW, Tier 2)
export const handleError: HandleServerError = async ({ error, event, status, message }) => {
	const errorId = crypto.randomUUID();

	console.error(`[${errorId}] Error in ${event.url.pathname}:`, error);

	return {
		message: (error as Error)?.message || message,
		errorId,
		stack: (error as Error)?.stack,
		path: event.url.pathname,
		timestamp: new Date().toISOString()
	};
};

// ============================================================
// Types
// ============================================================

declare global {
	namespace App {
		interface Locals {
			user: any;
			session: any;
		}
		interface Error {
			message: string;
			errorId?: string;
			stack?: string;
			path?: string;
			timestamp?: string;
		}
	}
}
