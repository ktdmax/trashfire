import type { PageServerLoad, Actions } from './$types';
import { db, getTrendingRecipes, searchRecipes, rawQuery } from '$lib/server/db';
import { recipes, users, follows } from '../../drizzle/schema';
import { eq, desc, and } from 'drizzle-orm';
import { fail, redirect } from '@sveltejs/kit';

// ============================================================
// Home page — trending recipes, featured cooks, search
// ============================================================

export const load: PageServerLoad = async ({ url, locals, cookies }) => {
	const searchTerm = url.searchParams.get('q') || '';
	const cuisine = url.searchParams.get('cuisine') || '';
	const difficulty = url.searchParams.get('difficulty') || '';
	const sort = url.searchParams.get('sort') || 'trending';
	const page = parseInt(url.searchParams.get('page') || '1');

	// BUG-087: Search term passed directly to raw SQL query function — SQL injection via search parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	let recipeList;
	if (searchTerm || cuisine || difficulty) {
		recipeList = searchRecipes(searchTerm, cuisine, difficulty);
	} else if (sort === 'trending') {
		// BUG-088: Sort parameter from URL passed to trending query — SQL injection via sort param (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
		recipeList = getTrendingRecipes(20, sort);
	} else {
		recipeList = db.select({
			id: recipes.id,
			title: recipes.title,
			slug: recipes.slug,
			description: recipes.description,
			coverImage: recipes.coverImage,
			authorId: recipes.authorId,
			avgRating: recipes.avgRating,
			viewCount: recipes.viewCount,
			prepTime: recipes.prepTime,
			cookTime: recipes.cookTime,
			servings: recipes.servings,
			cuisine: recipes.cuisine,
			difficulty: recipes.difficulty,
			tags: recipes.tags,
			createdAt: recipes.createdAt,
			authorName: users.username,
			authorDisplayName: users.displayName,
			authorAvatar: users.avatarUrl
		})
		.from(recipes)
		.innerJoin(users, eq(recipes.authorId, users.id))
		.where(eq(recipes.isPublic, true))
		.orderBy(desc(recipes.createdAt))
		.limit(20)
		.offset((page - 1) * 20)
		.all();
	}

	// Featured cooks — top rated authors
	const featuredCooks = db.select({
		id: users.id,
		username: users.username,
		displayName: users.displayName,
		avatarUrl: users.avatarUrl,
		bio: users.bio
	})
	.from(users)
	.where(eq(users.isVerified, true))
	.limit(6)
	.all();

	// Cuisine categories
	const cuisines = rawQuery('SELECT DISTINCT cuisine FROM recipes WHERE cuisine IS NOT NULL AND is_public = 1 ORDER BY cuisine');

	return {
		recipes: recipeList,
		featuredCooks,
		cuisines,
		searchTerm,
		cuisine,
		difficulty,
		sort,
		page,
		// BUG-089: User preferences loaded from unsigned cookie — cookie tampering can alter display behavior (CWE-565, CVSS 3.1, LOW, Tier 3)
		preferences: JSON.parse(cookies.get('preferences') || '{}')
	};
};

// ============================================================
// Home page actions — follow/unfollow, newsletter signup
// ============================================================

export const actions: Actions = {
	follow: async ({ request, locals }) => {
		if (!locals.user) {
			throw redirect(303, '/login');
		}

		const data = await request.formData();
		const targetUserId = data.get('userId') as string;

		if (!targetUserId) {
			return fail(400, { message: 'User ID required' });
		}

		// BUG-090: No check preventing users from following themselves (CWE-20, CVSS 3.1, LOW, Tier 3)
		// Check if already following
		const existing = db.select()
			.from(follows)
			.where(
				and(
					eq(follows.followerId, locals.user.id),
					eq(follows.followingId, targetUserId)
				)
			)
			.get();

		if (existing) {
			// Unfollow
			rawQuery('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [locals.user.id, targetUserId]);
		} else {
			// Follow
			db.insert(follows).values({
				followerId: locals.user.id,
				followingId: targetUserId
			}).run();
		}

		return { success: true };
	},

	newsletter: async ({ request }) => {
		const data = await request.formData();
		const email = data.get('email') as string;

		if (!email || !email.includes('@')) {
			return fail(400, { message: 'Valid email required' });
		}

		// BUG-091: Email stored via raw query with string interpolation — SQL injection (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
		rawQuery(`INSERT OR IGNORE INTO newsletter_subscribers (email, subscribed_at) VALUES ('${email}', unixepoch())`);

		return { success: true, message: 'Subscribed!' };
	},

	setPreferences: async ({ request, cookies }) => {
		const data = await request.formData();
		const prefs = {
			layout: data.get('layout') || 'grid',
			recipesPerPage: parseInt(data.get('recipesPerPage') as string) || 20,
			theme: data.get('theme') || 'light'
		};

		// BUG-092: Preferences cookie set without httpOnly — accessible to client-side scripts (CWE-1004, CVSS 3.1, BEST_PRACTICE, Tier 3)
		cookies.set('preferences', JSON.stringify(prefs), {
			path: '/',
			maxAge: 365 * 24 * 60 * 60,
			httpOnly: false,
			secure: false,
			sameSite: 'none'
		});

		return { success: true };
	}
};
