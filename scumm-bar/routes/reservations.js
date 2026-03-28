const express = require('express');
const router = express.Router();
const Reservation = require('../models/Reservation');
const { isAuthenticated, isStaff } = require('../middleware/auth');

// POST /reservations — create new reservation
router.post('/', async (req, res) => {
  try {
    // BUG-074: No CSRF protection on reservation creation (CWE-352, CVSS 6.5, MEDIUM, Tier 1)
    const reservationData = req.body;

    // Assign customer if logged in
    if (req.session && req.session.userId) {
      reservationData.customer = req.session.userId;
    }

    // Check table availability
    if (reservationData.tableNumber) {
      const conflict = await Reservation.findOne({
        tableNumber: reservationData.tableNumber,
        date: reservationData.date,
        time: reservationData.time,
        status: { $in: ['pending', 'confirmed'] },
      });

      if (conflict) {
        return res.status(409).json({ error: 'Table is already reserved for this time' });
      }
    }

    const reservation = new Reservation(reservationData);
    reservation.generateConfirmation();
    await reservation.save();

    res.status(201).json({
      message: 'Reservation created',
      reservation: {
        reservationNumber: reservation.reservationNumber,
        confirmationCode: reservation.confirmationCode,
        date: reservation.date,
        time: reservation.time,
        tableNumber: reservation.tableNumber,
        partySize: reservation.partySize,
        status: reservation.status,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /reservations — list reservations
router.get('/', isAuthenticated, async (req, res) => {
  try {
    let query = {};

    if (req.session.role === 'customer') {
      query.customer = req.session.userId;
    }

    if (req.query.date) {
      query.date = new Date(req.query.date);
    }

    if (req.query.status) {
      query.status = req.query.status;
    }

    // BUG-075: NoSQL injection via nested query operators in req.query (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
    // If req.query.partySize is {$gt: 0}, it bypasses expected filtering
    if (req.query.partySize) {
      query.partySize = req.query.partySize;
    }

    const reservations = await Reservation.find(query)
      .populate('customer', 'username email phone')
      .populate('assignedServer', 'username')
      .sort({ date: 1, time: 1 });

    res.json(reservations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /reservations/:number
router.get('/:number', async (req, res) => {
  try {
    // BUG-076: IDOR — any user (even unauthenticated) can view any reservation by number (CWE-639, CVSS 6.5, HIGH, Tier 1)
    const reservation = await Reservation.findOne({
      reservationNumber: parseInt(req.params.number)
    }).populate('customer', 'username email phone');

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    res.json(reservation);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /reservations/:number — update reservation
router.put('/:number', async (req, res) => {
  try {
    const { confirmationCode } = req.query;
    const reservation = await Reservation.findOne({
      reservationNumber: parseInt(req.params.number),
    });

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    // BUG-077: Weak auth — 4-char hex confirmation code is easily brute-forced (CWE-330, CVSS 5.3, TRICKY, Tier 2)
    // Combined with BUG-038: only 65536 possible values
    if (!req.session.userId && reservation.confirmationCode !== confirmationCode) {
      return res.status(403).json({ error: 'Invalid confirmation code' });
    }

    const updates = req.body;
    // BUG-078: Can change status to 'confirmed' bypassing staff approval (CWE-284, CVSS 5.3, MEDIUM, Tier 1)
    Object.assign(reservation, updates);
    await reservation.save();

    res.json(reservation);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /reservations/:number — cancel reservation
router.delete('/:number', async (req, res) => {
  try {
    const reservation = await Reservation.findOne({
      reservationNumber: parseInt(req.params.number),
    });

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    // BUG-079: No authorization check — anyone can cancel any reservation (CWE-862, CVSS 7.5, HIGH, Tier 1)
    reservation.status = 'cancelled';
    reservation.cancelledAt = new Date();
    reservation.cancellationReason = req.body.reason || 'Cancelled by user';
    await reservation.save();

    res.json({ message: 'Reservation cancelled', reservation });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /reservations/available-tables
router.get('/available-tables', async (req, res) => {
  try {
    const { date, time, partySize } = req.query;

    if (!date || !time) {
      return res.status(400).json({ error: 'Date and time required' });
    }

    const tables = await Reservation.getAvailableTables(
      new Date(date),
      time,
      parseInt(partySize) || 2
    );

    res.json({ availableTables: tables });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /reservations/lookup — lookup by confirmation code
router.post('/lookup', async (req, res) => {
  try {
    // BUG-080: NoSQL injection on confirmation code lookup (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
    const reservation = await Reservation.findOne({
      confirmationCode: req.body.confirmationCode,
    });

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    res.json(reservation);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
