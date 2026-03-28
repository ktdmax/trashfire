import type { LayoutServerLoad } from './$types';
import { db } from '$lib/server/db';
import { notifications, users } from '../../drizzle/schema';
import { eq, and } from 'drizzle-orm';

// ============================================================
// Root layout server load — provides global data to all pages
// ============================================================

export const load: LayoutServerLoad = async ({ locals, cookies, url }) => {
	const user = locals.user;
	const session = locals.session;

	if (user) {
		// BUG-084: Full user object including password hash and API key sent to every page (CWE-200, CVSS 7.5, HIGH, Tier 1)
		// Fetch full user record including sensitive fields
		const fullUser = db.select().from(users).where(eq(users.id, user.id)).get();

		// Fetch unread notification count
		const unreadNotifications = db.select()
			.from(notifications)
			.where(
				and(
					eq(notifications.userId, user.id),
					eq(notifications.isRead, false)
				)
			)
			.all();

		return {
			// BUG-085: User object returned with password, apiKey, resetToken — all exposed to client (CWE-200, CVSS 8.1, CRITICAL, Tier 1)
			user: fullUser,
			session: {
				id: session.id,
				expiresAt: session.expiresAt
			},
			notifications: unreadNotifications,
			notificationCount: unreadNotifications.length,
			// BUG-086: Debug mode flag derived from cookie — attackable by setting cookie manually (CWE-565, CVSS 4.3, LOW, Tier 2)
			debug: cookies.get('debug') === 'true',
			currentPath: url.pathname
		};
	}

	return {
		user: null,
		session: null,
		notifications: [],
		notificationCount: 0,
		debug: cookies.get('debug') === 'true',
		currentPath: url.pathname
	};
};
