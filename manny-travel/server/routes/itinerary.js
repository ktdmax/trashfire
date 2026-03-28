const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate } = require('../middleware/auth');
const { calculateTotalCost } = require('../../shared/pricing');
const config = require('../config');

/**
 * Get all itineraries for current user
 * GET /api/itineraries
 */
router.get('/', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT i.*, COUNT(ii.id) as item_count
       FROM itineraries i
       LEFT JOIN itinerary_items ii ON i.id = ii.itinerary_id
       WHERE i.user_id = $1
       GROUP BY i.id
       ORDER BY i.created_at DESC`,
      [req.user.id]
    );

    res.json({ itineraries: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch itineraries' });
  }
});

/**
 * Create itinerary
 * POST /api/itineraries
 */
router.post('/', authenticate, async (req, res) => {
  try {
    const { title, description, startDate, endDate, destination, isPublic } = req.body;

    if (!title || !startDate || !endDate) {
      return res.status(400).json({ error: 'Title, start date, and end date are required' });
    }

    const result = await db.query(
      `INSERT INTO itineraries (user_id, title, description, start_date, end_date, destination, is_public, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING *`,
      [req.user.id, title, description, startDate, endDate, destination, isPublic || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create itinerary' });
  }
});

/**
 * Get itinerary by ID
 * GET /api/itineraries/:id
 */
router.get('/:id', authenticate, async (req, res) => {
  try {
    const itinerary = await db.query(
      'SELECT * FROM itineraries WHERE id = $1',
      [req.params.id]
    );

    if (itinerary.rows.length === 0) {
      return res.status(404).json({ error: 'Itinerary not found' });
    }

    const itin = itinerary.rows[0];

    // BUG-0082: IDOR — non-public itineraries accessible without ownership check (CWE-639, CVSS 6.5, LOW, Tier 2)
    // Should check: if (!itin.is_public && itin.user_id !== req.user.id)

    // Get items
    const items = await db.query(
      `SELECT ii.*, b.status as booking_status, b.total_price as booking_price
       FROM itinerary_items ii
       LEFT JOIN bookings b ON ii.booking_id = b.id
       WHERE ii.itinerary_id = $1
       ORDER BY ii.day_number, ii.sort_order`,
      [req.params.id]
    );

    itin.items = items.rows;

    // Calculate total cost using shared pricing
    const costs = items.rows
      .filter(item => item.booking_price)
      .map(item => parseFloat(item.booking_price));
    itin.totalEstimatedCost = calculateTotalCost(costs);

    res.json(itin);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch itinerary' });
  }
});

/**
 * Update itinerary
 * PUT /api/itineraries/:id
 */
router.put('/:id', authenticate, async (req, res) => {
  try {
    const { title, description, startDate, endDate, destination, isPublic } = req.body;

    // Check ownership
    const existing = await db.query(
      'SELECT user_id FROM itineraries WHERE id = $1',
      [req.params.id]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Itinerary not found' });
    }

    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const result = await db.query(
      `UPDATE itineraries SET
        title = COALESCE($1, title),
        description = COALESCE($2, description),
        start_date = COALESCE($3, start_date),
        end_date = COALESCE($4, end_date),
        destination = COALESCE($5, destination),
        is_public = COALESCE($6, is_public),
        updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [title, description, startDate, endDate, destination, isPublic, req.params.id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update itinerary' });
  }
});

/**
 * Add item to itinerary
 * POST /api/itineraries/:id/items
 */
router.post('/:id/items', authenticate, async (req, res) => {
  try {
    const { type, bookingId, dayNumber, sortOrder, title, description, location, startTime, endTime, notes } = req.body;

    // BUG-0083: No ownership check before adding items — anyone can add items to any itinerary (CWE-639, CVSS 6.5, HIGH, Tier 2)
    const result = await db.query(
      `INSERT INTO itinerary_items (itinerary_id, type, booking_id, day_number, sort_order, title, description, location, start_time, end_time, notes, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
       RETURNING *`,
      [req.params.id, type, bookingId || null, dayNumber, sortOrder || 0, title, description, location, startTime, endTime, notes]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add itinerary item' });
  }
});

/**
 * Remove item from itinerary
 * DELETE /api/itineraries/:id/items/:itemId
 */
router.delete('/:id/items/:itemId', authenticate, async (req, res) => {
  try {
    // BUG-0084: No ownership check on item deletion (CWE-639, CVSS 5.5, LOW, Tier 2)
    const result = await db.query(
      'DELETE FROM itinerary_items WHERE id = $1 AND itinerary_id = $2',
      [req.params.itemId, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }

    res.json({ message: 'Item removed' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove item' });
  }
});

/**
 * Share itinerary via link
 * POST /api/itineraries/:id/share
 */
router.post('/:id/share', authenticate, async (req, res) => {
  try {
    const { email } = req.body;

    const itinerary = await db.query(
      'SELECT * FROM itineraries WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (itinerary.rows.length === 0) {
      return res.status(404).json({ error: 'Itinerary not found' });
    }

    const crypto = require('crypto');
    const shareToken = crypto.randomBytes(16).toString('hex');

    await db.query(
      `INSERT INTO itinerary_shares (itinerary_id, share_token, shared_with_email, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [req.params.id, shareToken, email]
    );

    // Send share notification
    if (email) {
      const notifications = require('../services/notifications');
      await notifications.sendItineraryShare(email, req.user.name, itinerary.rows[0].title, shareToken);
    }

    // BUG-0085: Open redirect — share URL constructed from user-supplied origin parameter (CWE-601, CVSS 5.5, LOW, Tier 2)
    const baseUrl = req.body.origin || req.headers.origin || 'https://mannytravel.com';
    const shareUrl = `${baseUrl}/itinerary/shared/${shareToken}`;

    res.json({ shareUrl, shareToken });
  } catch (error) {
    res.status(500).json({ error: 'Failed to share itinerary' });
  }
});

/**
 * Access shared itinerary
 * GET /api/itineraries/shared/:token
 */
router.get('/shared/:token', async (req, res) => {
  try {
    const share = await db.query(
      `SELECT s.*, i.*, u.name as owner_name
       FROM itinerary_shares s
       JOIN itineraries i ON s.itinerary_id = i.id
       JOIN users u ON i.user_id = u.id
       WHERE s.share_token = $1`,
      [req.params.token]
    );

    if (share.rows.length === 0) {
      return res.status(404).json({ error: 'Shared itinerary not found' });
    }

    const itinerary = share.rows[0];

    const items = await db.query(
      `SELECT * FROM itinerary_items WHERE itinerary_id = $1 ORDER BY day_number, sort_order`,
      [itinerary.itinerary_id]
    );

    itinerary.items = items.rows;

    res.json(itinerary);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch shared itinerary' });
  }
});

/**
 * Clone an itinerary
 * POST /api/itineraries/:id/clone
 */
router.post('/:id/clone', authenticate, async (req, res) => {
  try {
    const original = await db.query(
      'SELECT * FROM itineraries WHERE id = $1',
      [req.params.id]
    );

    if (original.rows.length === 0) {
      return res.status(404).json({ error: 'Itinerary not found' });
    }

    const orig = original.rows[0];

    // BUG-0086: Cloning private itineraries without checking access permissions (CWE-639, CVSS 5.5, LOW, Tier 2)
    const newItin = await db.query(
      `INSERT INTO itineraries (user_id, title, description, start_date, end_date, destination, is_public, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, false, NOW())
       RETURNING *`,
      [req.user.id, `Copy of ${orig.title}`, orig.description, orig.start_date, orig.end_date, orig.destination]
    );

    // Clone items
    const items = await db.query(
      'SELECT * FROM itinerary_items WHERE itinerary_id = $1',
      [req.params.id]
    );

    for (const item of items.rows) {
      await db.query(
        `INSERT INTO itinerary_items (itinerary_id, type, day_number, sort_order, title, description, location, start_time, end_time, notes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
        [newItin.rows[0].id, item.type, item.day_number, item.sort_order, item.title, item.description, item.location, item.start_time, item.end_time, item.notes]
      );
    }

    res.status(201).json(newItin.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to clone itinerary' });
  }
});

/**
 * Delete itinerary
 * DELETE /api/itineraries/:id
 */
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM itineraries WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Itinerary not found or not authorized' });
    }

    res.json({ message: 'Itinerary deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete itinerary' });
  }
});

module.exports = router;
