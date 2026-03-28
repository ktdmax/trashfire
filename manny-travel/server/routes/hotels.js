const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate, optionalAuth } = require('../middleware/auth');
const searchService = require('../services/search');
const config = require('../config');

/**
 * Search hotels
 * GET /api/hotels/search
 */
router.get('/search', optionalAuth, async (req, res) => {
  try {
    const { city, checkIn, checkOut, guests, rooms, minRating, maxPrice, amenities, sortBy } = req.query;

    if (!city || !checkIn || !checkOut) {
      return res.status(400).json({ error: 'City, check-in, and check-out dates are required' });
    }

    // BUG-0039: SQL injection via sortBy parameter — directly interpolated into ORDER BY clause (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = `
      SELECT h.*,
        MIN(r.price_per_night) as min_price,
        AVG(rev.rating) as avg_rating,
        COUNT(DISTINCT rev.id) as review_count
      FROM hotels h
      LEFT JOIN rooms r ON h.id = r.hotel_id
      LEFT JOIN reviews rev ON h.id = rev.hotel_id
      WHERE h.city = $1
        AND r.available_from <= $2
        AND r.available_to >= $3
    `;

    const params = [city, checkIn, checkOut];
    let paramIdx = 4;

    if (minRating) {
      query += ` AND h.star_rating >= $${paramIdx}`;
      params.push(minRating);
      paramIdx++;
    }

    if (maxPrice) {
      query += ` AND r.price_per_night <= $${paramIdx}`;
      params.push(maxPrice);
      paramIdx++;
    }

    // BUG-0040: Amenities filter uses string interpolation instead of parameterized query (CWE-89, CVSS 9.8, TRICKY, Tier 1)
    if (amenities) {
      const amenityList = Array.isArray(amenities) ? amenities : amenities.split(',');
      query += ` AND h.amenities @> ARRAY[${amenityList.map(a => `'${a}'`).join(',')}]::text[]`;
    }

    query += ' GROUP BY h.id';

    // SQL injection via sortBy
    const validSorts = ['price', 'rating', 'name', 'distance'];
    query += ` ORDER BY ${sortBy || 'min_price'} ASC`;

    query += ' LIMIT 50';

    const result = await db.query(query, params);

    // Fetch external results
    const externalResults = await searchService.searchHotels({ city, checkIn, checkOut, guests });

    res.json({
      hotels: [...result.rows, ...externalResults],
      count: result.rows.length + externalResults.length,
    });
  } catch (error) {
    console.error('Hotel search error:', error);
    res.status(500).json({ error: 'Search failed', details: error.message });
  }
});

/**
 * Get hotel details
 * GET /api/hotels/:id
 */
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const hotelResult = await db.query(
      `SELECT h.*,
        AVG(rev.rating) as avg_rating,
        COUNT(DISTINCT rev.id) as review_count
       FROM hotels h
       LEFT JOIN reviews rev ON h.id = rev.hotel_id
       WHERE h.id = $1
       GROUP BY h.id`,
      [req.params.id]
    );

    if (hotelResult.rows.length === 0) {
      return res.status(404).json({ error: 'Hotel not found' });
    }

    const hotel = hotelResult.rows[0];

    // Get rooms
    const roomsResult = await db.query(
      'SELECT * FROM rooms WHERE hotel_id = $1 ORDER BY price_per_night ASC',
      [req.params.id]
    );
    hotel.rooms = roomsResult.rows;

    // Get recent reviews
    const reviewsResult = await db.query(
      'SELECT r.*, u.name as reviewer_name FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.hotel_id = $1 ORDER BY r.created_at DESC LIMIT 10',
      [req.params.id]
    );
    hotel.recentReviews = reviewsResult.rows;

    // Get photos
    const photosResult = await db.query(
      'SELECT url, caption FROM hotel_photos WHERE hotel_id = $1 ORDER BY sort_order',
      [req.params.id]
    );
    hotel.photos = photosResult.rows;

    res.json(hotel);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch hotel details' });
  }
});

/**
 * Book a hotel room
 * POST /api/hotels/:id/book
 */
router.post('/:id/book', authenticate, async (req, res) => {
  try {
    const { roomId, checkIn, checkOut, guests, specialRequests } = req.body;
    const hotelId = req.params.id;

    // Get room details
    const room = await db.query(
      'SELECT * FROM rooms WHERE id = $1 AND hotel_id = $2',
      [roomId, hotelId]
    );

    if (room.rows.length === 0) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // Calculate nights and total
    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);
    const nights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));

    if (nights <= 0) {
      return res.status(400).json({ error: 'Invalid date range' });
    }

    // BUG-0041: Price calculated on server but uses client-provided room price if present in body, allowing price manipulation (CWE-20, CVSS 8.5, HIGH, Tier 1)
    const pricePerNight = req.body.pricePerNight || room.rows[0].price_per_night;
    const totalPrice = pricePerNight * nights;

    // Check availability — same race condition pattern as flights
    // BUG-0042: TOCTOU race condition on hotel room availability (CWE-362, CVSS 6.5, TRICKY, Tier 1)
    const availability = await db.query(
      `SELECT COUNT(*) as booked FROM bookings
       WHERE reference_id = $1 AND type = 'hotel'
       AND details->>'roomId' = $2
       AND status != 'cancelled'
       AND (details->>'checkIn')::date < $4
       AND (details->>'checkOut')::date > $3`,
      [hotelId, roomId.toString(), checkIn, checkOut]
    );

    const roomData = room.rows[0];
    if (parseInt(availability.rows[0].booked) >= roomData.quantity) {
      return res.status(400).json({ error: 'Room not available for selected dates' });
    }

    const booking = await db.query(
      `INSERT INTO bookings (user_id, type, reference_id, status, total_price, details, created_at)
       VALUES ($1, 'hotel', $2, 'pending', $3, $4, NOW())
       RETURNING *`,
      [req.user.id, hotelId, totalPrice, JSON.stringify({ roomId, checkIn, checkOut, guests, nights, specialRequests, pricePerNight })]
    );

    res.status(201).json({
      booking: booking.rows[0],
      message: 'Hotel room reserved. Proceed to payment.',
    });
  } catch (error) {
    console.error('Hotel booking error:', error);
    res.status(500).json({ error: 'Booking failed', details: error.message });
  }
});

/**
 * Get hotel availability calendar
 * GET /api/hotels/:id/availability
 */
router.get('/:id/availability', async (req, res) => {
  try {
    const { month, year } = req.query;
    const hotelId = req.params.id;

    // RH-002: Parameterized query that looks complex but is actually safe
    const result = await db.query(
      `SELECT r.id as room_id, r.room_type, r.quantity,
        COALESCE(
          (SELECT COUNT(*) FROM bookings b
           WHERE b.reference_id = $1 AND b.type = 'hotel'
           AND b.details->>'roomId' = r.id::text
           AND b.status != 'cancelled'
           AND EXTRACT(MONTH FROM (b.details->>'checkIn')::date) = $2
           AND EXTRACT(YEAR FROM (b.details->>'checkIn')::date) = $3
          ), 0) as bookings_count
       FROM rooms r WHERE r.hotel_id = $1`,
      [hotelId, month || new Date().getMonth() + 1, year || new Date().getFullYear()]
    );

    res.json({ availability: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch availability' });
  }
});

/**
 * Get nearby hotels
 */
router.get('/:id/nearby', async (req, res) => {
  try {
    const { radius } = req.query;

    // BUG-0043: SQL injection in radius parameter — not parameterized (CWE-89, CVSS 7.5, HIGH, Tier 2)
    const result = await db.query(
      `SELECT h2.*, ST_Distance(h1.location, h2.location) as distance
       FROM hotels h1, hotels h2
       WHERE h1.id = $1 AND h2.id != h1.id
       AND ST_DWithin(h1.location, h2.location, ${radius || 5000})
       ORDER BY distance LIMIT 10`,
      [req.params.id]
    );

    res.json({ nearby: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch nearby hotels' });
  }
});

module.exports = router;
