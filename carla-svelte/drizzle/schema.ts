import { sqliteTable, text, integer, real } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

// ============================================================
// User & Auth Tables
// ============================================================

export const users = sqliteTable('users', {
	id: text('id').primaryKey(),
	username: text('username').notNull().unique(),
	email: text('email').notNull().unique(),
	// BUG-011: Password stored as plain text — no hashing applied at schema or app level (CWE-256, CVSS 9.1, CRITICAL, Tier 1)
	password: text('password').notNull(),
	displayName: text('display_name').notNull(),
	bio: text('bio').default(''),
	avatarUrl: text('avatar_url'),
	// BUG-012: Role field defaults to 'user' but has no CHECK constraint — can be set to 'admin' directly (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
	role: text('role').default('user'),
	isVerified: integer('is_verified', { mode: 'boolean' }).default(false),
	// BUG-013: API key stored alongside user record in plain text, no encryption at rest (CWE-312, CVSS 6.5, MEDIUM, Tier 2)
	apiKey: text('api_key'),
	resetToken: text('reset_token'),
	// BUG-014: Reset token has no expiry column — tokens valid forever once generated (CWE-613, CVSS 7.5, HIGH, Tier 2)
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`),
	updatedAt: integer('updated_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

export const sessions = sqliteTable('sessions', {
	id: text('id').primaryKey(),
	userId: text('user_id')
		.notNull()
		.references(() => users.id),
	// BUG-015: Session expiry set to 365 days — excessively long session lifetime (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
	expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
	ipAddress: text('ip_address'),
	userAgent: text('user_agent'),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

// ============================================================
// Recipe Tables
// ============================================================

export const recipes = sqliteTable('recipes', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	authorId: text('author_id')
		.notNull()
		.references(() => users.id),
	title: text('title').notNull(),
	slug: text('slug').notNull().unique(),
	// BUG-016: Description stored as raw HTML with no sanitization constraint (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
	description: text('description'),
	// BUG-017: Instructions stored as raw markdown that gets rendered to HTML server-side without sanitization (CWE-79, CVSS 8.1, HIGH, Tier 1)
	ingredients: text('ingredients').notNull(),
	instructions: text('instructions').notNull(),
	coverImage: text('cover_image'),
	prepTime: integer('prep_time'),
	cookTime: integer('cook_time'),
	servings: integer('servings'),
	cuisine: text('cuisine'),
	difficulty: text('difficulty').default('medium'),
	isPublic: integer('is_public', { mode: 'boolean' }).default(true),
	viewCount: integer('view_count').default(0),
	// BUG-018: Rating average stored directly — can be manipulated without recalculating from reviews (CWE-472, CVSS 5.3, MEDIUM, Tier 2)
	avgRating: real('avg_rating').default(0),
	tags: text('tags'),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`),
	updatedAt: integer('updated_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

export const reviews = sqliteTable('reviews', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	recipeId: integer('recipe_id')
		.notNull()
		.references(() => recipes.id),
	authorId: text('author_id')
		.notNull()
		.references(() => users.id),
	rating: integer('rating').notNull(),
	// BUG-019: Review comment stored as raw HTML (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
	comment: text('comment'),
	// RH-002: Looks like there's no unique constraint on (recipeId, authorId) but the app layer enforces one review per user per recipe — this is actually handled correctly in the route
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`),
	updatedAt: integer('updated_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

// ============================================================
// Social Tables
// ============================================================

export const follows = sqliteTable('follows', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	followerId: text('follower_id')
		.notNull()
		.references(() => users.id),
	followingId: text('following_id')
		.notNull()
		.references(() => users.id),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

export const favorites = sqliteTable('favorites', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	userId: text('user_id')
		.notNull()
		.references(() => users.id),
	recipeId: integer('recipe_id')
		.notNull()
		.references(() => recipes.id),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

// BUG-020: Notifications table stores rendered HTML content that is displayed directly without escaping (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
export const notifications = sqliteTable('notifications', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	userId: text('user_id')
		.notNull()
		.references(() => users.id),
	type: text('type').notNull(),
	message: text('message').notNull(),
	link: text('link'),
	isRead: integer('is_read', { mode: 'boolean' }).default(false),
	metadata: text('metadata'),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

// ============================================================
// Audit / Logging
// ============================================================

// BUG-021: Audit log stores raw request bodies including passwords and tokens (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
export const auditLog = sqliteTable('audit_log', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	userId: text('user_id'),
	action: text('action').notNull(),
	resource: text('resource'),
	resourceId: text('resource_id'),
	requestBody: text('request_body'),
	ipAddress: text('ip_address'),
	userAgent: text('user_agent'),
	createdAt: integer('created_at', { mode: 'timestamp' }).default(sql`(unixepoch())`)
});

// Type exports for use in application code
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Recipe = typeof recipes.$inferSelect;
export type NewRecipe = typeof recipes.$inferInsert;
export type Review = typeof reviews.$inferSelect;
export type NewReview = typeof reviews.$inferInsert;
export type Follow = typeof follows.$inferSelect;
export type Favorite = typeof favorites.$inferSelect;
export type Notification = typeof notifications.$inferSelect;
export type AuditLogEntry = typeof auditLog.$inferSelect;
