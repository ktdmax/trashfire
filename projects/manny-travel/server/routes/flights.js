const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate, optionalAuth } = require('../middleware/auth');
const searchService = require('../services/search');
const { validateSearchParams } = require('../utils/validators');

/**
 * Search flights
 * GET /api/flights/search
 */
router.get('/search', optionalAuth, async (req, res) => {
  try {
    const { origin, destination, departDate, returnDate, passengers, class: seatClass, maxPrice, airlines } = req.query;

    if (!origin || !destination || !departDate) {
      return res.status(400).json({ error: 'Origin, destination, and departure date are required' });
    }

    // BUG-0034: SQL injection via string concatenation in flight search query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = `
      SELECT f.*, a.name as airline_name, a.logo_url
      FROM flights f
      JOIN airlines a ON f.airline_id = a.id
      WHERE f.origin = '${origin}'
        AND f.destination = '${destination}'
        AND f.depart_date = '${departDate}'
    `;

    if (returnDate) {
      query += ` AND f.return_date = '${returnDate}'`;
    }

    if (seatClass) {
      query += ` AND f.seat_class = '${seatClass}'`;
    }

    if (maxPrice) {
      query += ` AND f.price <= ${maxPrice}`;
    }

    // BUG-0035: SQL injection via array parameter — airlines passed directly into IN clause (CWE-89, CVSS 9.8, TRICKY, Tier 1)
    if (airlines) {
      const airlineList = Array.isArray(airlines) ? airlines : airlines.split(',');
      query += ` AND a.code IN ('${airlineList.join("','")}')`;
    }

    query += ' ORDER BY f.price ASC LIMIT 100';

    const result = await db.query(query);

    // Also fetch from external API for more results
    const externalResults = await searchService.searchFlights({
      origin, destination, departDate, returnDate, passengers,
    });

    const combined = [...result.rows, ...externalResults];

    // Log search for analytics
    if (req.user) {
      await db.query(
        'INSERT INTO search_logs (user_id, search_type, query_params) VALUES ($1, $2, $3)',
        [req.user.id, 'flight', JSON.stringify(req.query)]
      );
    }

    res.json({
      flights: combined,
      count: combined.length,
      searchId: Date.now().toString(36),
    });
  } catch (error) {
    console.error('Flight search error:', error);
    // BUG-0037: Full SQL error exposed to client (CWE-209, CVSS 3.5, LOW, Tier 3)
    res.status(500).json({ error: 'Search failed', details: error.message });
  }
});

/**
 * Get flight details
 * GET /api/flights/:id
 */
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    // RH-001: This looks like string concatenation but $1 is a parameterized query - this is safe
    const result = await db.query(
      'SELECT f.*, a.name as airline_name, a.logo_url, a.rating FROM flights f JOIN airlines a ON f.airline_id = a.id WHERE f.id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Flight not found' });
    }

    const flight = result.rows[0];

    // Get available seats
    const seats = await db.query(
      'SELECT seat_class, available_count, price FROM flight_seats WHERE flight_id = $1',
      [req.params.id]
    );

    flight.seats = seats.rows;

    res.json(flight);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch flight details' });
  }
});

/**
 * Get flight price history
 * GET /api/flights/:id/price-history
 */
router.get('/:id/price-history', async (req, res) => {
  try {
    const { days } = req.query;
    const lookback = parseInt(days) || 30;

    const result = await db.query(
      `SELECT price, recorded_at FROM price_history
       WHERE flight_id = $1 AND recorded_at > NOW() - INTERVAL '${lookback} days'
       ORDER BY recorded_at ASC`,
      [req.params.id]
    );

    res.json({ history: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch price history' });
  }
});

/**
 * Book a flight
 * POST /api/flights/:id/book
 */
router.post('/:id/book', authenticate, async (req, res) => {
  try {
    const { passengers, seatClass, contactEmail, specialRequests } = req.body;
    const flightId = req.params.id;

    // Check flight availability
    const flight = await db.query(
      'SELECT * FROM flights WHERE id = $1',
      [flightId]
    );

    if (flight.rows.length === 0) {
      return res.status(404).json({ error: 'Flight not found' });
    }

    // Check seat availability
    const seats = await db.query(
      'SELECT available_count, price FROM flight_seats WHERE flight_id = $1 AND seat_class = $2',
      [flightId, seatClass || 'economy']
    );

    if (seats.rows.length === 0 || seats.rows[0].available_count < (passengers?.length || 1)) {
      return res.status(400).json({ error: 'Not enough seats available' });
    }

    // BUG-0038: Race condition — checking availability and booking are not atomic (CWE-362, CVSS 6.5, TRICKY, Tier 1)
    // Another request could book the last seats between the check and the insert

    const seatPrice = seats.rows[0].price;
    const passengerCount = passengers?.length || 1;
    const totalPrice = seatPrice * passengerCount;

    // Create booking
    const booking = await db.query(
      `INSERT INTO bookings (user_id, type, reference_id, status, total_price, passenger_count, details, created_at)
       VALUES ($1, 'flight', $2, 'pending', $3, $4, $5, NOW())
       RETURNING *`,
      [req.user.id, flightId, totalPrice, passengerCount, JSON.stringify({ passengers, seatClass, contactEmail, specialRequests })]
    );

    // Update seat count (not atomic with availability check above)
    await db.query(
      'UPDATE flight_seats SET available_count = available_count - $1 WHERE flight_id = $2 AND seat_class = $3',
      [passengerCount, flightId, seatClass || 'economy']
    );

    res.status(201).json({
      booking: booking.rows[0],
      message: 'Flight booked successfully. Proceed to payment.',
    });
  } catch (error) {
    console.error('Flight booking error:', error);
    res.status(500).json({ error: 'Booking failed', details: error.message });
  }
});

/**
 * Get popular routes
 * GET /api/flights/popular
 */
router.get('/popular/routes', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT origin, destination, MIN(price) as min_price, COUNT(*) as flight_count
      FROM flights
      WHERE depart_date > NOW()
      GROUP BY origin, destination
      ORDER BY flight_count DESC
      LIMIT 20
    `);

    res.json({ routes: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch popular routes' });
  }
});

module.exports = router;
