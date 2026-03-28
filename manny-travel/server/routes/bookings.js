const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const { calculateRefund } = require('../../shared/pricing');
const config = require('../config');

/**
 * Get all bookings for current user
 * GET /api/bookings
 */
router.get('/', authenticate, async (req, res) => {
  try {
    const { status, type, page, limit, sortBy, order } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = Math.min(parseInt(limit) || 20, config.pagination.maxLimit);
    const offset = (pageNum - 1) * limitNum;

    let query = 'SELECT * FROM bookings WHERE user_id = $1';
    const params = [req.user.id];
    let paramIdx = 2;

    if (status) {
      query += ` AND status = $${paramIdx}`;
      params.push(status);
      paramIdx++;
    }

    if (type) {
      query += ` AND type = $${paramIdx}`;
      params.push(type);
      paramIdx++;
    }

    // BUG-0044: SQL injection via sortBy parameter — column name not validated (CWE-89, CVSS 7.5, BEST_PRACTICE, Tier 2)
    query += ` ORDER BY ${sortBy || 'created_at'} ${order === 'asc' ? 'ASC' : 'DESC'}`;
    query += ` LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    params.push(limitNum, offset);

    const result = await db.query(query, params);

    // Count total
    const countResult = await db.query(
      'SELECT COUNT(*) FROM bookings WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      bookings: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: pageNum,
      limit: limitNum,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch bookings', details: error.message });
  }
});

/**
 * Get booking by ID
 * GET /api/bookings/:id
 */
router.get('/:id', authenticate, async (req, res) => {
  try {
    // BUG-0045: IDOR — no ownership check, any authenticated user can view any booking (CWE-639, CVSS 7.5, HIGH, Tier 1)
    const result = await db.query(
      'SELECT b.*, u.name as user_name, u.email as user_email FROM bookings b JOIN users u ON b.user_id = u.id WHERE b.id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Fetch associated details based on type
    if (booking.type === 'flight') {
      const flight = await db.query('SELECT * FROM flights WHERE id = $1', [booking.reference_id]);
      booking.flightDetails = flight.rows[0];
    } else if (booking.type === 'hotel') {
      const hotel = await db.query('SELECT * FROM hotels WHERE id = $1', [booking.reference_id]);
      booking.hotelDetails = hotel.rows[0];
    }

    res.json(booking);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch booking' });
  }
});

/**
 * Cancel booking
 * POST /api/bookings/:id/cancel
 */
router.post('/:id/cancel', authenticate, async (req, res) => {
  try {
    // BUG-0046: IDOR on cancellation — no ownership check (CWE-639, CVSS 8.1, LOW, Tier 1)
    const result = await db.query(
      'SELECT * FROM bookings WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    const booking = result.rows[0];

    if (booking.status === 'cancelled') {
      return res.status(400).json({ error: 'Booking already cancelled' });
    }

    // Calculate refund using shared pricing module
    // BUG-0047: Cross-module pricing bug — calculateRefund uses floating-point arithmetic that can produce incorrect refund amounts (CWE-682, CVSS 6.5, TRICKY, Tier 1)
    const refundAmount = calculateRefund(booking.total_price, booking.created_at, booking.type);

    await db.query(
      'UPDATE bookings SET status = $1, refund_amount = $2, cancelled_at = NOW() WHERE id = $3',
      ['cancelled', refundAmount, req.params.id]
    );

    // BUG-0048: Refund processed without verifying original payment was actually captured (CWE-840, CVSS 7.5, BEST_PRACTICE, Tier 2)
    if (refundAmount > 0) {
      await db.query(
        `INSERT INTO refunds (booking_id, amount, status, created_at)
         VALUES ($1, $2, 'pending', NOW())`,
        [req.params.id, refundAmount]
      );
    }

    res.json({
      message: 'Booking cancelled',
      refundAmount,
      booking: { ...booking, status: 'cancelled', refund_amount: refundAmount },
    });
  } catch (error) {
    console.error('Cancellation error:', error);
    res.status(500).json({ error: 'Cancellation failed', details: error.message });
  }
});

/**
 * Update booking details
 * PUT /api/bookings/:id
 */
router.put('/:id', authenticate, async (req, res) => {
  try {
    const { specialRequests, contactEmail, passengers } = req.body;

    // BUG-0049: IDOR — no ownership check on update (CWE-639, CVSS 7.5, LOW, Tier 1)
    const result = await db.query(
      'SELECT * FROM bookings WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    const booking = result.rows[0];
    const details = typeof booking.details === 'string' ? JSON.parse(booking.details) : booking.details;

    // Merge updates into details
    const updatedDetails = {
      ...details,
      specialRequests: specialRequests || details.specialRequests,
      contactEmail: contactEmail || details.contactEmail,
      passengers: passengers || details.passengers,
    };

    await db.query(
      'UPDATE bookings SET details = $1, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(updatedDetails), req.params.id]
    );

    res.json({ message: 'Booking updated', details: updatedDetails });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

/**
 * Get booking confirmation PDF
 * GET /api/bookings/:id/confirmation
 */
router.get('/:id/confirmation', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM bookings WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    // Generate confirmation reference
    const crypto = require('crypto');
    // RH-003: MD5 used here but only for generating a non-security-critical booking reference hash, not for passwords
    const refHash = crypto.createHash('md5').update(`${req.params.id}-${result.rows[0].created_at}`).digest('hex').substring(0, 8).toUpperCase();

    res.json({
      confirmation: {
        referenceNumber: `MT-${refHash}`,
        booking: result.rows[0],
        generatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate confirmation' });
  }
});

/**
 * Admin: Get all bookings
 * GET /api/bookings/admin/all
 */
router.get('/admin/all', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { page, limit } = req.query;
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 50;
    const offset = (pageNum - 1) * limitNum;

    const result = await db.query(
      `SELECT b.*, u.name as user_name, u.email as user_email
       FROM bookings b JOIN users u ON b.user_id = u.id
       ORDER BY b.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limitNum, offset]
    );

    const count = await db.query('SELECT COUNT(*) FROM bookings');

    res.json({
      bookings: result.rows,
      total: parseInt(count.rows[0].count),
      page: pageNum,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

/**
 * Bulk cancel bookings
 * POST /api/bookings/bulk/cancel
 */
router.post('/bulk/cancel', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { bookingIds, reason } = req.body;

    if (!Array.isArray(bookingIds) || bookingIds.length === 0) {
      return res.status(400).json({ error: 'Booking IDs required' });
    }

    // BUG-0050: SQL injection via array of booking IDs — directly interpolated (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    const result = await db.query(
      `UPDATE bookings SET status = 'cancelled', cancelled_at = NOW(),
       details = details || '{"cancelReason": "${reason}"}'::jsonb
       WHERE id IN (${bookingIds.join(',')})
       RETURNING *`
    );

    res.json({
      cancelled: result.rows.length,
      bookings: result.rows,
    });
  } catch (error) {
    res.status(500).json({ error: 'Bulk cancellation failed' });
  }
});

module.exports = router;
