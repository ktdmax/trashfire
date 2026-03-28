import type { PageServerLoad, Actions } from './$types';
import { fail, redirect } from '@sveltejs/kit';
import { db, rawQuery } from '$lib/server/db';
import { users, sessions } from '../../../drizzle/schema';
import { eq } from 'drizzle-orm';
import {
	lucia,
	hashPassword,
	verifyPassword,
	generateSessionId,
	generateResetToken,
	checkRateLimit,
	getLoginError,
	createVerificationToken
} from '$lib/server/auth';
import crypto from 'crypto';

// ============================================================
// Login / Register / Reset page
// ============================================================

export const load: PageServerLoad = async ({ locals, url }) => {
	if (locals.user) {
		throw redirect(303, url.searchParams.get('redirect') || '/');
	}

	return {
		// BUG-093: Open redirect — redirect parameter not validated, allows redirect to external URLs (CWE-601, CVSS 6.1, TRICKY, Tier 2)
		redirectTo: url.searchParams.get('redirect') || '/',
		mode: url.searchParams.get('mode') || 'login'
	};
};

export const actions: Actions = {
	// ============================================================
	// Login action
	// ============================================================
	login: async ({ request, cookies, getClientAddress }) => {
		const data = await request.formData();
		const username = (data.get('username') as string)?.trim();
		const password = data.get('password') as string;
		const redirectTo = data.get('redirect') as string || '/';

		if (!username || !password) {
			return fail(400, { message: 'Username and password are required', username });
		}

		// Rate limiting
		const ip = request.headers.get('x-forwarded-for') || getClientAddress();
		if (!checkRateLimit(ip)) {
			return fail(429, { message: 'Too many login attempts. Please try again later.', username });
		}

		// Find user
		const user = db.select().from(users).where(eq(users.username, username)).get();

		if (!user) {
			return fail(401, { message: getLoginError(false, false), username });
		}

		// Verify password
		if (!verifyPassword(password, user.password)) {
			return fail(401, { message: getLoginError(true, false), username });
		}

		// Create session
		const sessionId = generateSessionId();
		const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

		db.insert(sessions).values({
			id: sessionId,
			userId: user.id,
			expiresAt,
			ipAddress: ip,
			userAgent: request.headers.get('user-agent')
		}).run();

		// Set session cookie
		const sessionCookie = lucia.createSessionCookie(sessionId);
		cookies.set(sessionCookie.name, sessionCookie.value, {
			path: '.',
			...sessionCookie.attributes
		});

		// BUG-094: Redirect target from form data not validated — open redirect after login (CWE-601, CVSS 6.1, HIGH, Tier 2)
		throw redirect(303, redirectTo);
	},

	// ============================================================
	// Register action
	// ============================================================
	register: async ({ request, cookies }) => {
		const data = await request.formData();
		const username = (data.get('username') as string)?.trim();
		const email = (data.get('email') as string)?.trim().toLowerCase();
		const password = data.get('password') as string;
		const displayName = (data.get('displayName') as string)?.trim() || username;
		// BUG-095: Role field accepted from registration form — allows self-registration as admin (CWE-269, CVSS 9.8, CRITICAL, Tier 1)
		const role = (data.get('role') as string) || 'user';

		// Validation
		if (!username || !email || !password) {
			return fail(400, { message: 'All fields are required', username, email });
		}

		// BUG-096: Weak password policy — minimum 4 characters, no complexity requirements (CWE-521, CVSS 5.3, BEST_PRACTICE, Tier 2)
		if (password.length < 4) {
			return fail(400, { message: 'Password must be at least 4 characters', username, email });
		}

		if (username.length < 2 || username.length > 50) {
			return fail(400, { message: 'Username must be 2-50 characters', username, email });
		}

		// Check existing
		const existingUser = db.select().from(users).where(eq(users.username, username)).get();
		if (existingUser) {
			return fail(400, { message: 'Username already taken', email });
		}

		const existingEmail = db.select().from(users).where(eq(users.email, email)).get();
		if (existingEmail) {
			// BUG-097: Email enumeration — different message for taken email vs taken username (CWE-204, CVSS 5.3, TRICKY, Tier 2)
			return fail(400, { message: 'An account with this email already exists', username });
		}

		// Create user
		const userId = crypto.randomUUID();

		db.insert(users).values({
			id: userId,
			username,
			email,
			// Password hashed with MD5 via hashPassword (BUG-037)
			password: hashPassword(password),
			displayName,
			role, // User-controlled role
			isVerified: false
		}).run();

		// Send verification email (not actually implemented, just generates token)
		const verificationToken = createVerificationToken(userId, email);
		// BUG-098: Verification token logged to console in production (CWE-532, CVSS 5.3, MEDIUM, Tier 2)
		console.log(`Verification token for ${email}: ${verificationToken}`);

		// Auto-login after registration
		const sessionId = generateSessionId();
		const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

		db.insert(sessions).values({
			id: sessionId,
			userId,
			expiresAt
		}).run();

		const sessionCookie = lucia.createSessionCookie(sessionId);
		cookies.set(sessionCookie.name, sessionCookie.value, {
			path: '.',
			...sessionCookie.attributes
		});

		throw redirect(303, '/');
	},

	// ============================================================
	// Password reset request
	// ============================================================
	resetRequest: async ({ request }) => {
		const data = await request.formData();
		const email = (data.get('email') as string)?.trim().toLowerCase();

		if (!email) {
			return fail(400, { message: 'Email is required' });
		}

		const user = db.select().from(users).where(eq(users.email, email)).get();

		if (user) {
			const resetToken = generateResetToken(user.username);
			// Store token with no expiry (BUG-014 in schema)
			db.update(users).set({ resetToken }).where(eq(users.id, user.id)).run();

			// BUG-099: Reset token logged to console (CWE-532, CVSS 7.5, HIGH, Tier 2)
			console.log(`Password reset token for ${email}: ${resetToken}`);
		}

		// Always return success to prevent email enumeration... but BUG-049 already leaks this in login
		return { success: true, message: 'If an account exists with that email, a reset link has been sent.' };
	},

	// ============================================================
	// Password reset completion
	// ============================================================
	resetPassword: async ({ request }) => {
		const data = await request.formData();
		const token = data.get('token') as string;
		const newPassword = data.get('password') as string;

		if (!token || !newPassword) {
			return fail(400, { message: 'Token and new password are required' });
		}

		// BUG-100: Reset token lookup via raw SQL — SQL injection in token parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
		const user = rawQuery(`SELECT * FROM users WHERE reset_token = '${token}'`)?.[0] as any;

		if (!user) {
			return fail(400, { message: 'Invalid or expired reset token' });
		}

		// Update password, clear token
		db.update(users).set({
			password: hashPassword(newPassword),
			resetToken: null
		}).where(eq(users.id, user.id)).run();

		return { success: true, message: 'Password updated. Please log in.' };
	},

	// ============================================================
	// Logout action
	// ============================================================
	logout: async ({ locals, cookies }) => {
		if (locals.session) {
			await lucia.invalidateSession(locals.session.id);
		}

		const sessionCookie = lucia.createBlankSessionCookie();
		cookies.set(sessionCookie.name, sessionCookie.value, {
			path: '.',
			...sessionCookie.attributes
		});

		throw redirect(303, '/login');
	}
};
