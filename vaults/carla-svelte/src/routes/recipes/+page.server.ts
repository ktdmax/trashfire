import type { PageServerLoad, Actions } from './$types';
import { db, rawQuery, searchRecipes } from '$lib/server/db';
import { recipes, users, favorites, reviews } from '../../../drizzle/schema';
import { eq, desc, and } from 'drizzle-orm';
import { fail, redirect } from '@sveltejs/kit';
import { uploadFile } from '$lib/server/storage';
import { marked } from 'marked';

// ============================================================
// Recipe listing and creation
// ============================================================

export const load: PageServerLoad = async ({ url, locals }) => {
	const query = url.searchParams.get('q') || '';
	const cuisine = url.searchParams.get('cuisine') || '';
	const difficulty = url.searchParams.get('difficulty') || '';
	const tags = url.searchParams.get('tags') || '';
	const author = url.searchParams.get('author') || '';
	const sort = url.searchParams.get('sort') || 'newest';
	const page = parseInt(url.searchParams.get('page') || '1');
	const perPage = Math.min(parseInt(url.searchParams.get('perPage') || '24'), 100);

	let recipeList: any[];

	if (query || cuisine || difficulty) {
		// Uses vulnerable searchRecipes function (BUG-026)
		recipeList = searchRecipes(query, cuisine, difficulty);
	} else {
		let queryStr = `
			SELECT r.*, u.username as author_name, u.display_name as author_display, u.avatar_url as author_avatar,
				(SELECT COUNT(*) FROM reviews rv WHERE rv.recipe_id = r.id) as review_count,
				(SELECT COUNT(*) FROM favorites f WHERE f.recipe_id = r.id) as favorite_count
			FROM recipes r
			JOIN users u ON r.author_id = u.id
			WHERE r.is_public = 1
		`;

		if (author) {
			queryStr += ` AND u.username = '${author}'`;
		}

		if (tags) {
			queryStr += ` AND r.tags LIKE '%${tags}%'`;
		}

		// Sort handling
		const sortMap: Record<string, string> = {
			newest: 'r.created_at DESC',
			oldest: 'r.created_at ASC',
			popular: 'r.view_count DESC',
			rating: 'r.avg_rating DESC',
			title: 'r.title ASC'
		};

		// RH-007: Looks like sort parameter is injectable, but it's validated against sortMap keys — safe
		const sortClause = sortMap[sort] || sortMap.newest;
		queryStr += ` ORDER BY ${sortClause} LIMIT ${perPage} OFFSET ${(page - 1) * perPage}`;

		recipeList = rawQuery(queryStr);
	}

	// Get total count for pagination
	const totalCount = rawQuery('SELECT COUNT(*) as count FROM recipes WHERE is_public = 1')?.[0] as any;

	// Get cuisine options for filter
	const cuisineOptions = rawQuery('SELECT DISTINCT cuisine FROM recipes WHERE cuisine IS NOT NULL ORDER BY cuisine');

	return {
		recipes: recipeList,
		totalCount: totalCount?.count || 0,
		page,
		perPage,
		totalPages: Math.ceil((totalCount?.count || 0) / perPage),
		filters: { query, cuisine, difficulty, tags, author, sort },
		cuisineOptions
	};
};

export const actions: Actions = {
	// ============================================================
	// Create recipe action
	// ============================================================
	create: async ({ request, locals }) => {
		if (!locals.user) {
			throw redirect(303, '/login?redirect=/recipes');
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
		const isPublic = data.get('isPublic') !== 'false';
		const coverImageFile = data.get('coverImage') as File | null;

		// Validation
		if (!title || !ingredients || !instructions) {
			return fail(400, { message: 'Title, ingredients, and instructions are required' });
		}

		// Generate slug from title
		const slug = title
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-|-$/g, '')
			.slice(0, 80);

		// Process cover image
		let coverImageUrl: string | null = null;
		if (coverImageFile && coverImageFile.size > 0) {
			try {
				const result = await uploadFile(coverImageFile, locals.user.id, 'recipes');
				coverImageUrl = result.url;
			} catch (err: any) {
				return fail(400, { message: err.message || 'Failed to upload image' });
			}
		}

		// Insert recipe
		try {
			db.insert(recipes).values({
				authorId: locals.user.id,
				title,
				slug,
				description,
				ingredients: JSON.stringify(
					ingredients.split('\n').filter(Boolean).map(i => i.trim())
				),
				instructions,
				coverImage: coverImageUrl,
				prepTime,
				cookTime,
				servings,
				cuisine: cuisine || null,
				difficulty: difficulty || 'medium',
				isPublic,
				tags: tags || null
			}).run();

			throw redirect(303, `/recipes/${slug}`);
		} catch (err: any) {
			if (err.status === 303) throw err; // Re-throw redirect
			return fail(500, { message: 'Failed to create recipe' });
		}
	},

	// ============================================================
	// Bulk delete recipes (for admin/owner)
	// ============================================================
	bulkDelete: async ({ request, locals }) => {
		if (!locals.user) {
			throw redirect(303, '/login');
		}

		const data = await request.formData();
		const recipeIds = (data.get('recipeIds') as string)?.split(',');

		if (!recipeIds || recipeIds.length === 0) {
			return fail(400, { message: 'No recipes selected' });
		}

		// No ownership check or admin verification — any authenticated user can bulk delete
		const idList = recipeIds.join(',');
		rawQuery(`DELETE FROM recipes WHERE id IN (${idList})`);
		rawQuery(`DELETE FROM reviews WHERE recipe_id IN (${idList})`);
		rawQuery(`DELETE FROM favorites WHERE recipe_id IN (${idList})`);

		return { success: true, message: `Deleted ${recipeIds.length} recipes` };
	},

	// ============================================================
	// Import recipes from JSON
	// ============================================================
	import: async ({ request, locals }) => {
		if (!locals.user) {
			throw redirect(303, '/login');
		}

		const data = await request.formData();
		const jsonFile = data.get('file') as File;

		if (!jsonFile) {
			return fail(400, { message: 'No file provided' });
		}

		try {
			const content = await jsonFile.text();
			const recipesData = JSON.parse(content);

			if (!Array.isArray(recipesData)) {
				return fail(400, { message: 'Expected an array of recipes' });
			}

			let imported = 0;
			for (const r of recipesData) {
				db.insert(recipes).values({
					authorId: locals.user.id,
					title: r.title || 'Untitled',
					slug: r.slug || `imported-${Date.now()}-${imported}`,
					description: r.description || '',
					ingredients: typeof r.ingredients === 'string' ? r.ingredients : JSON.stringify(r.ingredients || []),
					instructions: r.instructions || '',
					coverImage: r.coverImage || null,
					prepTime: r.prepTime || 0,
					cookTime: r.cookTime || 0,
					servings: r.servings || 0,
					cuisine: r.cuisine || null,
					difficulty: r.difficulty || 'medium',
					isPublic: r.isPublic !== false,
					tags: r.tags || null,
					// Imported data can set avgRating directly — bypasses review system (BUG-018)
					avgRating: r.avgRating || 0
				}).run();
				imported++;
			}

			return { success: true, message: `Imported ${imported} recipes` };
		} catch (err: any) {
			return fail(400, { message: err.message || 'Failed to parse JSON file' });
		}
	}
};
