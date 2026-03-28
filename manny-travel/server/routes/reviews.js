const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { reviewLimiter } = require('../middleware/rateLimit');

/**
 * Get reviews for a hotel or flight
 * GET /api/reviews
 */
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { hotelId, flightId, airlineId, rating, sortBy, page, limit } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 20;
    const offset = (pageNum - 1) * limitNum;

    let query = `
      SELECT r.*, u.name as reviewer_name, u.avatar_url as reviewer_avatar
      FROM reviews r
      JOIN users u ON r.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramIdx = 1;

    if (hotelId) {
      query += ` AND r.hotel_id = $${paramIdx}`;
      params.push(hotelId);
      paramIdx++;
    }

    if (flightId) {
      query += ` AND r.flight_id = $${paramIdx}`;
      params.push(flightId);
      paramIdx++;
    }

    if (airlineId) {
      query += ` AND r.airline_id = $${paramIdx}`;
      params.push(airlineId);
      paramIdx++;
    }

    if (rating) {
      query += ` AND r.rating = $${paramIdx}`;
      params.push(parseInt(rating));
      paramIdx++;
    }

    // BUG-0077: SQL injection via sortBy — column name interpolated directly (CWE-89, CVSS 7.5, HIGH, Tier 2)
    query += ` ORDER BY ${sortBy || 'r.created_at'} DESC`;
    query += ` LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    params.push(limitNum, offset);

    const result = await db.query(query, params);

    res.json({
      reviews: result.rows,
      page: pageNum,
      limit: limitNum,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

/**
 * Create a review
 * POST /api/reviews
 */
router.post('/', authenticate, reviewLimiter, async (req, res) => {
  try {
    const { hotelId, flightId, airlineId, rating, title, body, photos } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    if (!title || !body) {
      return res.status(400).json({ error: 'Title and body are required' });
    }

    if (!hotelId && !flightId && !airlineId) {
      return res.status(400).json({ error: 'Must specify hotel, flight, or airline to review' });
    }

    // BUG-0078: Stored XSS — review title and body are stored without sanitization (CWE-79, CVSS 7.5, HIGH, Tier 1)
    // The body and title are inserted directly and will be rendered on the frontend
    const result = await db.query(
      `INSERT INTO reviews (user_id, hotel_id, flight_id, airline_id, rating, title, body, photos, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       RETURNING *`,
      [req.user.id, hotelId || null, flightId || null, airlineId || null, rating, title, body, JSON.stringify(photos || [])]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create review' });
  }
});

/**
 * Update a review
 * PUT /api/reviews/:id
 */
router.put('/:id', authenticate, async (req, res) => {
  try {
    const { rating, title, body, photos } = req.body;

    // Check ownership
    const existing = await db.query(
      'SELECT * FROM reviews WHERE id = $1',
      [req.params.id]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found' });
    }

    // BUG-0079: IDOR — ownership check fetches the review but doesn't compare user_id before updating (CWE-639, CVSS 6.5, HIGH, Tier 2)
    const result = await db.query(
      `UPDATE reviews SET
        rating = COALESCE($1, rating),
        title = COALESCE($2, title),
        body = COALESCE($3, body),
        photos = COALESCE($4, photos),
        updated_at = NOW()
       WHERE id = $5
       RETURNING *`,
      [rating, title, body, photos ? JSON.stringify(photos) : null, req.params.id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update review' });
  }
});

/**
 * Delete a review
 * DELETE /api/reviews/:id
 */
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM reviews WHERE id = $1 AND (user_id = $2 OR $3 = \'admin\')',
      [req.params.id, req.user.id, req.user.role]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Review not found or not authorized' });
    }

    res.json({ message: 'Review deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

/**
 * Flag a review
 * POST /api/reviews/:id/flag
 */
router.post('/:id/flag', authenticate, async (req, res) => {
  try {
    const { reason } = req.body;

    await db.query(
      `INSERT INTO review_flags (review_id, user_id, reason, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (review_id, user_id) DO NOTHING`,
      [req.params.id, req.user.id, reason]
    );

    res.json({ message: 'Review flagged for moderation' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to flag review' });
  }
});

/**
 * Get review statistics
 * GET /api/reviews/stats/:type/:id
 */
router.get('/stats/:type/:id', async (req, res) => {
  try {
    const { type, id } = req.params;
    let column;

    // BUG-0080: Potential SQL injection via type parameter — whitelist check is incomplete (CWE-89, CVSS 7.5, HIGH, Tier 2)
    switch (type) {
      case 'hotel': column = 'hotel_id'; break;
      case 'flight': column = 'flight_id'; break;
      case 'airline': column = 'airline_id'; break;
      default:
        // Falls through to query with undefined column — but type is used in query below
        column = type + '_id';
    }

    const result = await db.query(
      `SELECT
        COUNT(*) as total_reviews,
        AVG(rating)::numeric(3,2) as average_rating,
        COUNT(CASE WHEN rating = 5 THEN 1 END) as five_star,
        COUNT(CASE WHEN rating = 4 THEN 1 END) as four_star,
        COUNT(CASE WHEN rating = 3 THEN 1 END) as three_star,
        COUNT(CASE WHEN rating = 2 THEN 1 END) as two_star,
        COUNT(CASE WHEN rating = 1 THEN 1 END) as one_star
       FROM reviews WHERE ${column} = $1`,
      [id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch review stats' });
  }
});

/**
 * Helpful vote on a review
 * POST /api/reviews/:id/helpful
 */
router.post('/:id/helpful', authenticate, async (req, res) => {
  try {
    // Upsert helpful vote
    await db.query(
      `INSERT INTO review_helpful (review_id, user_id, created_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (review_id, user_id) DO NOTHING`,
      [req.params.id, req.user.id]
    );

    // Get updated count
    const count = await db.query(
      'SELECT COUNT(*) as helpful_count FROM review_helpful WHERE review_id = $1',
      [req.params.id]
    );

    res.json({ helpfulCount: parseInt(count.rows[0].helpful_count) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record vote' });
  }
});

/**
 * Get review responses/replies
 * GET /api/reviews/:id/responses
 */
router.get('/:id/responses', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT rr.*, u.name as responder_name
       FROM review_responses rr
       JOIN users u ON rr.user_id = u.id
       WHERE rr.review_id = $1
       ORDER BY rr.created_at ASC`,
      [req.params.id]
    );

    res.json({ responses: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch responses' });
  }
});

/**
 * Add response to review
 * POST /api/reviews/:id/respond
 */
router.post('/:id/respond', authenticate, async (req, res) => {
  try {
    const { body } = req.body;

    if (!body || body.trim().length === 0) {
      return res.status(400).json({ error: 'Response body is required' });
    }

    // BUG-0081: Stored XSS — response body not sanitized (CWE-79, CVSS 7.5, HIGH, Tier 2)
    const result = await db.query(
      `INSERT INTO review_responses (review_id, user_id, body, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [req.params.id, req.user.id, body]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add response' });
  }
});

module.exports = router;
