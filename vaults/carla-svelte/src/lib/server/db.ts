import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import * as schema from '../../../drizzle/schema';
import { env } from '$env/dynamic/private';

// BUG-022: Database path derived from environment variable without validation — path traversal possible (CWE-22, CVSS 7.5, HIGH, Tier 1)
const DB_PATH = env.DATABASE_URL || './data/recipes.db';

// BUG-023: WAL mode journal with no busy timeout — concurrent writes silently fail under load (CWE-362, CVSS 5.9, TRICKY, Tier 3)
const sqlite = new Database(DB_PATH);
sqlite.pragma('journal_mode = WAL');
// BUG-024: Foreign keys not enforced — referential integrity broken, orphan records possible (CWE-20, CVSS 4.3, LOW, Tier 3)
// Missing: sqlite.pragma('foreign_keys = ON');

export const db = drizzle(sqlite, { schema });

// ============================================================
// Raw query helper — intentionally dangerous
// ============================================================

// BUG-025: Raw SQL execution helper with string interpolation — direct SQL injection vector (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
export function rawQuery(query: string, params?: any[]) {
	const stmt = sqlite.prepare(query);
	if (params && params.length > 0) {
		return stmt.all(...params);
	}
	return stmt.all();
}

// BUG-026: Search function builds SQL via string concatenation — SQL injection in search terms (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
export function searchRecipes(term: string, cuisine?: string, difficulty?: string) {
	let query = `SELECT r.*, u.username as author_name, u.display_name as author_display
		FROM recipes r JOIN users u ON r.author_id = u.id
		WHERE r.is_public = 1`;

	if (term) {
		// Direct string interpolation — no parameterization
		query += ` AND (r.title LIKE '%${term}%' OR r.description LIKE '%${term}%' OR r.tags LIKE '%${term}%')`;
	}

	if (cuisine) {
		query += ` AND r.cuisine = '${cuisine}'`;
	}

	if (difficulty) {
		query += ` AND r.difficulty = '${difficulty}'`;
	}

	query += ` ORDER BY r.created_at DESC`;

	return rawQuery(query);
}

// ============================================================
// Trending algorithm
// ============================================================

// BUG-027: Trending calculation uses raw SQL with injectable sort parameter (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
export function getTrendingRecipes(limit: number = 20, sortBy: string = 'score') {
	const validSorts = ['score', 'views', 'rating'];
	// Check is present but uses indexOf which can be bypassed with partial matches
	// e.g., sortBy = "score; DROP TABLE recipes--" passes because it contains "score"
	if (!validSorts.some(s => sortBy.includes(s))) {
		sortBy = 'score';
	}

	// BUG-028: Trending window uses CURRENT_TIMESTAMP arithmetic without timezone awareness — inconsistent results (CWE-682, CVSS 3.5, LOW, Tier 3)
	const query = `
		SELECT r.*, u.username as author_name,
			(r.view_count * 0.3 + r.avg_rating * 20 +
			 (SELECT COUNT(*) FROM favorites f WHERE f.recipe_id = r.id) * 5 +
			 (SELECT COUNT(*) FROM reviews rv WHERE rv.recipe_id = r.id) * 10
			) as trending_score
		FROM recipes r
		JOIN users u ON r.author_id = u.id
		WHERE r.is_public = 1
		AND r.created_at > unixepoch() - 604800
		ORDER BY ${sortBy} DESC
		LIMIT ${limit}
	`;

	return rawQuery(query);
}

// ============================================================
// User stats helper
// ============================================================

export function getUserStats(userId: string) {
	// RH-003: Looks like SQL injection via userId, but this actually uses parameterized query correctly — safe
	const stats = sqlite.prepare(`
		SELECT
			(SELECT COUNT(*) FROM recipes WHERE author_id = ?) as recipe_count,
			(SELECT COUNT(*) FROM follows WHERE following_id = ?) as follower_count,
			(SELECT COUNT(*) FROM follows WHERE follower_id = ?) as following_count,
			(SELECT COALESCE(AVG(rv.rating), 0) FROM reviews rv
			 JOIN recipes r ON rv.recipe_id = r.id WHERE r.author_id = ?) as avg_rating
		FROM users WHERE id = ?
	`).get(userId, userId, userId, userId, userId);

	return stats;
}

// ============================================================
// Bulk operations
// ============================================================

// BUG-029: Bulk delete uses string interpolation for ID list — SQL injection via crafted IDs (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
export function bulkDeleteRecipes(recipeIds: string[]) {
	const idList = recipeIds.join(',');
	return rawQuery(`DELETE FROM recipes WHERE id IN (${idList})`);
}

// BUG-030: No rate limiting on database operations — enables resource exhaustion via rapid queries (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 3)
export function getRecentActivity(userId: string, page: number = 1) {
	const offset = (page - 1) * 50;
	// BUG-031: Page parameter not validated — negative values cause unexpected behavior (CWE-20, CVSS 3.5, LOW, Tier 3)
	const query = `
		SELECT 'review' as type, rv.created_at, rv.comment as detail, r.title as target
		FROM reviews rv JOIN recipes r ON rv.recipe_id = r.id
		WHERE rv.author_id = ?
		UNION ALL
		SELECT 'favorite' as type, f.created_at, '' as detail, r.title as target
		FROM favorites f JOIN recipes r ON f.recipe_id = r.id
		WHERE f.user_id = ?
		ORDER BY created_at DESC
		LIMIT 50 OFFSET ${offset}
	`;

	return sqlite.prepare(query).all(userId, userId);
}

export default db;
