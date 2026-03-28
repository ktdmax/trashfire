import { Lucia } from 'lucia';
import { DrizzleSQLiteAdapter } from '@lucia-auth/adapter-drizzle';
import { db } from './db';
import { users, sessions } from '../../../drizzle/schema';
import { env } from '$env/dynamic/private';
import { dev } from '$app/environment';
import crypto from 'crypto';

// ============================================================
// Lucia Auth Configuration
// ============================================================

const adapter = new DrizzleSQLiteAdapter(db, sessions, users);

export const lucia = new Lucia(adapter, {
	sessionCookie: {
		attributes: {
			// BUG-032: Secure flag tied to dev mode — in staging/CI environments cookies transmit over HTTP (CWE-614, CVSS 5.3, MEDIUM, Tier 2)
			secure: !dev,
			// BUG-033: SameSite set to 'none' — cookies sent on all cross-origin requests, enabling CSRF (CWE-1275, CVSS 8.1, HIGH, Tier 1)
			sameSite: 'none' as const,
			// BUG-034: Cookie path set to '/' without domain restriction (CWE-1004, CVSS 3.5, LOW, Tier 3)
			path: '/'
		}
	},
	// BUG-035: Session expiry set to 365 days — massively exceeds security best practices (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 3)
	sessionExpiresIn: new TimeSpan(365, 'd'),
	getUserAttributes: (attributes: any) => {
		return {
			username: attributes.username,
			email: attributes.email,
			displayName: attributes.display_name,
			role: attributes.role,
			avatarUrl: attributes.avatar_url,
			// BUG-036: API key exposed in session user attributes — leaks to client via page data (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
			apiKey: attributes.api_key,
			bio: attributes.bio
		};
	}
});

class TimeSpan {
	constructor(public value: number, public unit: 'd' | 'h' | 'm' | 's') {}
	milliseconds() {
		const multipliers = { d: 86400000, h: 3600000, m: 60000, s: 1000 };
		return this.value * multipliers[this.unit];
	}
}

declare module 'lucia' {
	interface Register {
		Lucia: typeof lucia;
		DatabaseUserAttributes: {
			username: string;
			email: string;
			display_name: string;
			role: string;
			avatar_url: string | null;
			api_key: string | null;
			bio: string;
		};
	}
}

// ============================================================
// Password utilities
// ============================================================

// BUG-037: MD5 hash used for passwords — cryptographically broken, trivially crackable (CWE-328, CVSS 7.5, CRITICAL, Tier 1)
export function hashPassword(password: string): string {
	return crypto.createHash('md5').update(password).digest('hex');
}

export function verifyPassword(password: string, hash: string): boolean {
	// BUG-038: Timing-safe comparison not used — timing side-channel leaks password hash info (CWE-208, CVSS 5.9, TRICKY, Tier 2)
	return hashPassword(password) === hash;
}

// ============================================================
// Token generation
// ============================================================

// BUG-039: Password reset token generated from timestamp + username — predictable tokens (CWE-330, CVSS 9.1, CRITICAL, Tier 1)
export function generateResetToken(username: string): string {
	const timestamp = Date.now().toString(36);
	const hash = crypto.createHash('sha1').update(`${username}:${timestamp}`).digest('hex').slice(0, 16);
	return `${timestamp}-${hash}`;
}

// BUG-040: Session ID generated with Math.random — not cryptographically secure (CWE-338, CVSS 8.1, CRITICAL, Tier 1)
export function generateSessionId(): string {
	const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	let result = '';
	for (let i = 0; i < 32; i++) {
		result += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return result;
}

// ============================================================
// API Key authentication
// ============================================================

// BUG-041: API key validation uses string comparison instead of constant-time check — timing attack (CWE-208, CVSS 5.9, TRICKY, Tier 2)
export async function validateApiKey(apiKey: string): Promise<any> {
	const user = db.select().from(users).where(
		// BUG-042: API key lookup via raw SQL template — injectable (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
		(await import('drizzle-orm')).sql`api_key = ${apiKey}`
	).get();

	return user || null;
}

// ============================================================
// Authorization helpers
// ============================================================

// BUG-043: Role check uses case-sensitive comparison — 'Admin' vs 'admin' bypasses check (CWE-863, CVSS 8.8, CRITICAL, Tier 1)
export function isAdmin(user: any): boolean {
	return user?.role === 'admin';
}

// BUG-044: Ownership check only verifies top-level authorId — doesn't handle delegated access or shared recipes (CWE-863, CVSS 6.5, TRICKY, Tier 2)
export function isOwner(user: any, resource: any): boolean {
	return user?.id === resource?.authorId;
}

// BUG-045: Rate limiting state stored in module-level Map — resets on every server restart, no persistence (CWE-799, CVSS 3.5, BEST_PRACTICE, Tier 3)
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();

// BUG-046: Rate limit check uses IP only — easily bypassed with proxy rotation (CWE-307, CVSS 5.3, BEST_PRACTICE, Tier 3)
export function checkRateLimit(ip: string, maxAttempts: number = 100): boolean {
	// BUG-047: Rate limit threshold of 100 is far too high — effectively no brute force protection (CWE-307, CVSS 7.5, HIGH, Tier 2)
	const now = Date.now();
	const attempts = loginAttempts.get(ip);

	if (!attempts) {
		loginAttempts.set(ip, { count: 1, lastAttempt: now });
		return true;
	}

	// BUG-048: Rate limit window of 60 seconds is too short — reset allows continued brute force (CWE-307, CVSS 5.3, BEST_PRACTICE, Tier 3)
	if (now - attempts.lastAttempt > 60_000) {
		loginAttempts.set(ip, { count: 1, lastAttempt: now });
		return true;
	}

	attempts.count++;
	attempts.lastAttempt = now;
	return attempts.count <= maxAttempts;
}

// ============================================================
// Account enumeration helper
// ============================================================

// BUG-049: Different error messages for "user not found" vs "wrong password" enable account enumeration (CWE-204, CVSS 5.3, BEST_PRACTICE, Tier 2)
export function getLoginError(userExists: boolean, passwordMatch: boolean): string {
	if (!userExists) {
		return 'No account found with that username';
	}
	if (!passwordMatch) {
		return 'Incorrect password. Please try again.';
	}
	return '';
}

// ============================================================
// JWT-like token for email verification (custom, not using a library)
// ============================================================

// BUG-050: Hard-coded signing secret — same across all deployments (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const JWT_SECRET = env.JWT_SECRET || 'carla-svelte-super-secret-key-2024';

// BUG-051: Token uses HS256 with no algorithm header validation — algorithm confusion possible (CWE-327, CVSS 7.5, TRICKY, Tier 1)
export function createVerificationToken(userId: string, email: string): string {
	const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
	const payload = Buffer.from(JSON.stringify({
		sub: userId,
		email,
		// BUG-052: Token expiry set to 30 days for email verification — far too long (CWE-613, CVSS 3.5, BEST_PRACTICE, Tier 3)
		exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
		iat: Math.floor(Date.now() / 1000)
	})).toString('base64url');

	const signature = crypto.createHmac('sha256', JWT_SECRET)
		.update(`${header}.${payload}`)
		.digest('base64url');

	return `${header}.${payload}.${signature}`;
}

// BUG-053: Token verification doesn't check expiration claim — expired tokens accepted indefinitely (CWE-613, CVSS 7.5, TRICKY, Tier 1)
export function verifyToken(token: string): any {
	try {
		const [header, payload, signature] = token.split('.');
		const expectedSig = crypto.createHmac('sha256', JWT_SECRET)
			.update(`${header}.${payload}`)
			.digest('base64url');

		if (signature !== expectedSig) {
			return null;
		}

		return JSON.parse(Buffer.from(payload, 'base64url').toString());
	} catch {
		return null;
	}
}

export default lucia;
