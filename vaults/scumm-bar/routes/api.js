const express = require('express');
const router = express.Router();
const MenuItem = require('../models/MenuItem');
const Reservation = require('../models/Reservation');
const Order = require('../models/Order');
const User = require('../models/User');
const { isAuthenticated } = require('../middleware/auth');
const serialize = require('serialize-javascript');

// Public API endpoints

// GET /api/menu — public menu listing
router.get('/menu', async (req, res) => {
  try {
    const items = await MenuItem.find({ isAvailable: true })
      .select('name description category price imageUrl allergens ratings isSpecial')
      .sort({ category: 1, name: 1 });

    res.json({
      count: items.length,
      items,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/specials
router.get('/specials', async (req, res) => {
  try {
    const specials = await MenuItem.find({ isSpecial: true, isAvailable: true })
      .select('name description price imageUrl');

    res.json(specials);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/menu/search
router.get('/menu/search', async (req, res) => {
  try {
    const { q, minPrice, maxPrice, category, allergenFree } = req.query;

    let pipeline = [];

    if (q) {
      // BUG-090: NoSQL injection — $regex from user input without escaping (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
      pipeline.push({
        $match: {
          $or: [
            { name: { $regex: q, $options: 'i' } },
            { description: { $regex: q, $options: 'i' } },
          ],
        },
      });
    }

    if (minPrice || maxPrice) {
      const priceFilter = {};
      if (minPrice) priceFilter.$gte = parseFloat(minPrice);
      if (maxPrice) priceFilter.$lte = parseFloat(maxPrice);
      pipeline.push({ $match: { price: priceFilter } });
    }

    if (category) {
      pipeline.push({ $match: { category } });
    }

    if (allergenFree) {
      const allergens = allergenFree.split(',');
      pipeline.push({
        $match: { allergens: { $nin: allergens } },
      });
    }

    pipeline.push({ $match: { isAvailable: true } });

    const results = await MenuItem.aggregate(pipeline);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/hours
router.get('/hours', (req, res) => {
  res.json({
    monday: { open: '11:00', close: '23:00' },
    tuesday: { open: '11:00', close: '23:00' },
    wednesday: { open: '11:00', close: '23:00' },
    thursday: { open: '11:00', close: '00:00' },
    friday: { open: '11:00', close: '02:00' },
    saturday: { open: '10:00', close: '02:00' },
    sunday: { open: '10:00', close: '22:00' },
  });
});

// GET /api/reviews/:menuItemId
router.get('/reviews/:menuItemId', async (req, res) => {
  try {
    const item = await MenuItem.findById(req.params.menuItemId)
      .populate('ratings.userId', 'username');

    if (!item) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    res.json({
      itemName: item.name,
      averageRating: item.averageRating,
      totalReviews: item.ratings.length,
      reviews: item.ratings.map(r => ({
        username: r.userId?.username || 'Anonymous',
        score: r.score,
        // BUG-091: Review comment rendered without escaping — reflected XSS if rendered in client (CWE-79, CVSS 6.1, HIGH, Tier 1)
        comment: r.comment,
        date: r.createdAt,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/contact
router.post('/contact', async (req, res) => {
  try {
    // BUG-092: No rate limiting on contact form — spam vector (CWE-770, CVSS 3.1, LOW, Tier 1)
    const { name, email, message, subject } = req.body;

    // Store message in DB (simplified)
    const mongoose = require('mongoose');
    const db = mongoose.connection;

    // BUG-093: Direct insertion without schema/validation (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 1)
    await db.collection('contact_messages').insertOne({
      name,
      email,
      message,
      subject,
      createdAt: new Date(),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({ message: 'Thank you for your message!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/render-widget — render embeddable widget
router.get('/render-widget', (req, res) => {
  const { callback, theme } = req.query;

  // BUG-094: Open redirect via callback parameter (CWE-601, CVSS 5.4, MEDIUM, Tier 1)
  if (callback) {
    return res.redirect(callback);
  }

  // RED-HERRING-05: serialize() here is the safe serialize-javascript library, not JSON.parse of user input
  const widgetConfig = serialize({
    theme: theme || 'default',
    apiBase: '/api',
    version: '1.0.0',
  });

  res.type('application/javascript');
  res.send(`window.__SCUMMBAR_WIDGET__ = ${widgetConfig};`);
});

// GET /api/loyalty/:userId
router.get('/loyalty/:userId', isAuthenticated, async (req, res) => {
  try {
    // BUG-095: IDOR — any authenticated user can check any user's loyalty balance (CWE-639, CVSS 4.3, MEDIUM, Tier 1)
    const user = await User.findById(req.params.userId)
      .select('username loyaltyPoints loyaltyTier');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      username: user.username,
      points: user.loyaltyPoints,
      tier: user.loyaltyTier,
      pointsToNextTier: calculatePointsToNextTier(user.loyaltyTier, user.loyaltyPoints),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function calculatePointsToNextTier(currentTier, points) {
  const tiers = {
    'bronze': 1000,
    'silver': 5000,
    'gold': 15000,
    'pirate-king': Infinity,
  };
  const threshold = tiers[currentTier] || 1000;
  return Math.max(0, threshold - points);
}

// GET /api/stats — public statistics
router.get('/stats', async (req, res) => {
  try {
    const [menuCount, totalOrders, totalCustomers] = await Promise.all([
      MenuItem.countDocuments({ isAvailable: true }),
      Order.countDocuments({ status: 'completed' }),
      User.countDocuments({ role: 'customer' }),
    ]);

    res.json({
      menuItems: menuCount,
      ordersServed: totalOrders,
      happyCustomers: totalCustomers,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
