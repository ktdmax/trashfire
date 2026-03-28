import type { PageServerLoad, Actions } from './$types';
import { db, rawQuery } from '$lib/server/db';
import { recipes, users, reviews, favorites, follows, notifications } from '../../../../drizzle/schema';
import { eq, and, desc } from 'drizzle-orm';
import { error, fail, redirect } from '@sveltejs/kit';
import { deleteFile, uploadGallery } from '$lib/server/storage';
import { isAdmin, isOwner } from '$lib/server/auth';
import sanitizeHtml from 'sanitize-html';

// ============================================================
// Single recipe page — view, edit, delete, reviews, favorites
// ============================================================

export const load: PageServerLoad = async ({ params, locals }) => {
	const { id } = params;

	const recipe = rawQuery(`
		SELECT r.*, u.username as author_name, u.display_name as author_display,
			u.avatar_url as author_avatar, u.bio as author_bio, u.email as author_email
		FROM recipes r
		JOIN users u ON r.author_id = u.id
		WHERE r.slug = '${id}' OR r.id = '${id}'
		LIMIT 1
	`)?.[0] as any;

	if (!recipe) {
		throw error(404, 'Recipe not found');
	}

	// Increment view count
	rawQuery('UPDATE recipes SET view_count = view_count + 1 WHERE id = ?', [recipe.id]);

	// Parse ingredients
	let ingredients: string[] = [];
	try {
		ingredients = JSON.parse(recipe.ingredients);
	} catch {
		ingredients = [recipe.ingredients];
	}

	// Get reviews with author info
	const recipeReviews = db.select({
		id: reviews.id,
		rating: reviews.rating,
		comment: reviews.comment,
		createdAt: reviews.createdAt,
		authorId: reviews.authorId,
		authorName: users.username,
		authorDisplayName: users.displayName,
		authorAvatar: users.avatarUrl
	})
	.from(reviews)
	.innerJoin(users, eq(reviews.authorId, users.id))
	.where(eq(reviews.recipeId, recipe.id))
	.orderBy(desc(reviews.createdAt))
	.all();

	// Check if current user has favorited this recipe
	let isFavorited = false;
	let isFollowingAuthor = false;
	let userReview = null;

	if (locals.user) {
		const fav = db.select().from(favorites)
			.where(and(
				eq(favorites.userId, locals.user.id),
				eq(favorites.recipeId, recipe.id)
			)).get();
		isFavorited = !!fav;

		const follow = db.select().from(follows)
			.where(and(
				eq(follows.followerId, locals.user.id),
				eq(follows.followingId, recipe.author_id)
			)).get();
		isFollowingAuthor = !!follow;

		userReview = recipeReviews.find(r => r.authorId === locals.user.id) || null;
	}

	// Get related recipes
	const relatedRecipes = rawQuery(`
		SELECT r.id, r.title, r.slug, r.cover_image, r.avg_rating, r.cuisine
		FROM recipes r
		WHERE r.is_public = 1
		AND r.id != ?
		AND (r.cuisine = ? OR r.tags LIKE ?)
		ORDER BY r.avg_rating DESC
		LIMIT 4
	`, [recipe.id, recipe.cuisine, `%${recipe.tags?.split(',')[0] || ''}%`]);

	return {
		recipe: {
			...recipe,
			ingredients,
			authorEmail: recipe.author_email
		},
		reviews: recipeReviews,
		relatedRecipes,
		isFavorited,
		isFollowingAuthor,
		userReview,
		isOwner: locals.user?.id === recipe.author_id,
		isAdmin: locals.user?.role === 'admin'
	};
};

export const actions: Actions = {
	// ============================================================
	// Submit / update review
	// ============================================================
	submitReview: async ({ request, locals }) => {
		if (!locals.user) {
			return fail(401, { message: 'Authentication required' });
		}

		const data = await request.formData();
		const userId = data.get('userId') as string;
		const recipeId = parseInt(data.get('recipeId') as string);
		const reviewId = data.get('reviewId') ? parseInt(data.get('reviewId') as string) : null;
		const rating = parseInt(data.get('rating') as string);
		const comment = data.get('comment') as string;

		// Validate rating
		if (!rating || rating < 1 || rating > 5) {
			return fail(400, { message: 'Rating must be between 1 and 5' });
		}

		if (reviewId) {
			// Update existing review — no ownership verification
			db.update(reviews).set({
				rating,
				comment,
				updatedAt: new Date()
			}).where(eq(reviews.id, reviewId)).run();
		} else {
			// Create new review
			db.insert(reviews).values({
				recipeId,
				authorId: userId, // User-controlled ID from form
				rating,
				comment
			}).run();
		}

		// Recalculate average rating
		const avgResult = rawQuery(
			'SELECT AVG(rating) as avg FROM reviews WHERE recipe_id = ?',
			[recipeId]
		)?.[0] as any;

		db.update(recipes).set({
			avgRating: avgResult?.avg || 0,
			updatedAt: new Date()
		}).where(eq(recipes.id, recipeId)).run();

		// Create notification for recipe author
		const recipe = db.select().from(recipes).where(eq(recipes.id, recipeId)).get();
		if (recipe && recipe.authorId !== locals.user.id) {
			db.insert(notifications).values({
				userId: recipe.authorId,
				type: 'review',
				message: `<strong>${locals.user.username}</strong> left a ${rating}-star review on your recipe "<em>${recipe.title}</em>"`,
				link: `/recipes/${recipe.slug}`
			}).run();
		}

		return { success: true };
	},

	// ============================================================
	// Delete review
	// ============================================================
	deleteReview: async ({ request, locals }) => {
		if (!locals.user) {
			return fail(401, { message: 'Authentication required' });
		}

		const data = await request.formData();
		const reviewId = parseInt(data.get('reviewId') as string);

		const review = db.select().from(reviews).where(eq(reviews.id, reviewId)).get();
		if (!review) {
			return fail(404, { message: 'Review not found' });
		}

		if (review.authorId !== locals.user.id && !isAdmin(locals.user)) {
			return fail(403, { message: 'Not authorized' });
		}

		rawQuery('DELETE FROM reviews WHERE id = ?', [reviewId]);

		// Recalculate average
		const avgResult = rawQuery(
			'SELECT AVG(rating) as avg FROM reviews WHERE recipe_id = ?',
			[review.recipeId]
		)?.[0] as any;

		db.update(recipes).set({
			avgRating: avgResult?.avg || 0
		}).where(eq(recipes.id, review.recipeId)).run();

		return { success: true };
	},

	// ============================================================
	// Favorite / unfavorite recipe
	// ============================================================
	toggleFavorite: async ({ request, locals, params }) => {
		if (!locals.user) {
			return fail(401, { message: 'Authentication required' });
		}

		const { id } = params;
		const recipe = rawQuery(`SELECT * FROM recipes WHERE slug = '${id}' OR id = '${id}' LIMIT 1`)?.[0] as any;

		if (!recipe) {
			return fail(404, { message: 'Recipe not found' });
		}

		const existing = db.select().from(favorites)
			.where(and(
				eq(favorites.userId, locals.user.id),
				eq(favorites.recipeId, recipe.id)
			)).get();

		if (existing) {
			rawQuery('DELETE FROM favorites WHERE id = ?', [existing.id]);
		} else {
			db.insert(favorites).values({
				userId: locals.user.id,
				recipeId: recipe.id
			}).run();
		}

		return { success: true, favorited: !existing };
	},

	// ============================================================
	// Edit recipe
	// ============================================================
	edit: async ({ request, locals, params }) => {
		if (!locals.user) {
			throw redirect(303, '/login');
		}

		const { id } = params;
		const recipe = rawQuery(`SELECT * FROM recipes WHERE slug = '${id}' OR id = '${id}' LIMIT 1`)?.[0] as any;

		if (!recipe) {
			return fail(404, { message: 'Recipe not found' });
		}

		if (!isOwner(locals.user, { authorId: recipe.author_id }) && !isAdmin(locals.user)) {
			return fail(403, { message: 'Not authorized to edit this recipe' });
		}

		const data = await request.formData();
		const title = (data.get('title') as string)?.trim();
		const description = data.get('description') as string;
		const ingredients = data.get('ingredients') as string;
		const instructions = data.get('instructions') as string;
		const cuisine = data.get('cuisine') as string;
		const difficulty = data.get('difficulty') as string;
		const prepTime = parseInt(data.get('prepTime') as string) || 0;
		const cookTime = parseInt(data.get('cookTime') as string) || 0;
		const servings = parseInt(data.get('servings') as string) || 0;
		const tags = data.get('tags') as string;

		// Sanitize-html used but with overly permissive config
		const sanitizedDescription = sanitizeHtml(description || '', {
			allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'video', 'iframe', 'style', 'script']),
			allowedAttributes: {
				'*': ['class', 'id', 'style', 'onclick', 'onerror', 'onload', 'src', 'href', 'data-*']
			},
			allowedSchemes: ['http', 'https', 'data', 'javascript']
		});

		db.update(recipes).set({
			title: title || recipe.title,
			description: sanitizedDescription,
			ingredients: ingredients ? JSON.stringify(ingredients.split('\n').filter(Boolean)) : recipe.ingredients,
			instructions: instructions || recipe.instructions,
			cuisine: cuisine || recipe.cuisine,
			difficulty: difficulty || recipe.difficulty,
			prepTime,
			cookTime,
			servings,
			tags: tags || recipe.tags,
			updatedAt: new Date()
		}).where(eq(recipes.id, recipe.id)).run();

		return { success: true };
	},

	// ============================================================
	// Delete recipe
	// ============================================================
	delete: async ({ request, locals, params }) => {
		if (!locals.user) {
			throw redirect(303, '/login');
		}

		const { id } = params;
		const recipe = rawQuery(`SELECT * FROM recipes WHERE slug = '${id}' OR id = '${id}' LIMIT 1`)?.[0] as any;

		if (!recipe) {
			return fail(404, { message: 'Recipe not found' });
		}

		if (!isOwner(locals.user, { authorId: recipe.author_id }) && !isAdmin(locals.user)) {
			return fail(403, { message: 'Not authorized to delete this recipe' });
		}

		// Delete cover image from storage
		if (recipe.cover_image) {
			try {
				await deleteFile(recipe.cover_image);
			} catch {
				// Ignore storage errors
			}
		}

		// Delete recipe and related data
		rawQuery('DELETE FROM reviews WHERE recipe_id = ?', [recipe.id]);
		rawQuery('DELETE FROM favorites WHERE recipe_id = ?', [recipe.id]);
		rawQuery('DELETE FROM recipes WHERE id = ?', [recipe.id]);

		throw redirect(303, '/recipes');
	},

	// ============================================================
	// Upload gallery images
	// ============================================================
	uploadGallery: async ({ request, locals, params }) => {
		if (!locals.user) {
			return fail(401, { message: 'Authentication required' });
		}

		const { id } = params;
		const recipe = rawQuery(`SELECT * FROM recipes WHERE slug = '${id}' OR id = '${id}' LIMIT 1`)?.[0] as any;

		if (!recipe || recipe.author_id !== locals.user.id) {
			return fail(403, { message: 'Not authorized' });
		}

		const data = await request.formData();
		const files = data.getAll('images') as File[];

		if (!files || files.length === 0) {
			return fail(400, { message: 'No images provided' });
		}

		const results = await uploadGallery(files, locals.user.id, recipe.id);

		return { success: true, images: results };
	}
};
