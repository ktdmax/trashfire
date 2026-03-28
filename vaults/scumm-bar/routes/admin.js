const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Order = require('../models/Order');
const Reservation = require('../models/Reservation');
const Inventory = require('../models/Inventory');
const MenuItem = require('../models/MenuItem');
const { isAuthenticated, isAdmin } = require('../middleware/auth');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { deepMerge } = require('../utils/helpers');

// GET /admin/dashboard
router.get('/dashboard', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const [userCount, orderCount, reservationCount, revenue] = await Promise.all([
      User.countDocuments(),
      Order.countDocuments(),
      Reservation.countDocuments({ date: { $gte: new Date() } }),
      Order.aggregate([
        { $match: { paymentStatus: 'paid' } },
        { $group: { _id: null, total: { $sum: '$total' } } },
      ]),
    ]);

    res.json({
      users: userCount,
      orders: orderCount,
      upcomingReservations: reservationCount,
      totalRevenue: revenue[0]?.total || 0,
      serverTime: new Date(),
      nodeVersion: process.version,
      // BUG-081: Exposes memory usage and uptime to admin panel (CWE-200, CVSS 3.1, LOW, Tier 1)
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /admin/users
router.get('/users', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // BUG-082: Returns all user data including password hashes (CWE-200, CVSS 7.5, HIGH, Tier 1)
    const users = await User.find({});
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /admin/users/:id/role
router.put('/users/:id/role', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'Role updated', user: { id: user._id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /admin/backup — create database backup
router.post('/backup', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const backupDir = req.body.backupDir || path.join(__dirname, '..', 'backups');

    // BUG-083: Command injection via backupDir parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    exec(`mongodump --uri="${process.env.MONGO_URI || 'mongodb://localhost:27017/scummbar'}" --out="${backupDir}"`, (error, stdout, stderr) => {
      if (error) {
        return res.status(500).json({ error: 'Backup failed', details: stderr });
      }
      res.json({ message: 'Backup completed', path: backupDir, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /admin/settings — update application settings
router.post('/settings', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const settingsPath = path.join(__dirname, '..', 'config', 'settings.json');
    let currentSettings = {};

    if (fs.existsSync(settingsPath)) {
      // BUG-084: Synchronous file read blocks event loop (CWE-400, CVSS 3.1, BEST_PRACTICE, Tier 1)
      const raw = fs.readFileSync(settingsPath, 'utf8');
      currentSettings = JSON.parse(raw);
    }

    // BUG-085: Prototype pollution via deep merge of user-controlled object (CWE-1321, CVSS 9.8, CRITICAL, Tier 3)
    const newSettings = deepMerge(currentSettings, req.body);

    fs.writeFileSync(settingsPath, JSON.stringify(newSettings, null, 2));

    res.json({ message: 'Settings updated', settings: newSettings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /admin/logs
router.get('/logs', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const logFile = req.query.file || 'app.log';

    // BUG-086: Path traversal — can read any file on the server (CWE-22, CVSS 8.6, CRITICAL, Tier 1)
    const logPath = path.join(__dirname, '..', 'logs', logFile);
    const content = fs.readFileSync(logPath, 'utf8');

    res.json({ file: logFile, content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /admin/inventory/auto-order
router.post('/inventory/auto-order', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const fetch = require('node-fetch');
    const lowItems = await Inventory.getLowStockItems();
    const results = [];

    for (const item of lowItems) {
      if (item.supplier && item.supplier.orderUrl) {
        // BUG-087: SSRF — fetches supplier URL which could be internal service (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
        try {
          const response = await fetch(item.supplier.orderUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sku: item.sku,
              quantity: item.reorderQuantity,
              supplier: item.supplier.name,
            }),
          });
          results.push({ item: item.name, status: 'ordered', response: await response.text() });
        } catch (fetchErr) {
          results.push({ item: item.name, status: 'failed', error: fetchErr.message });
        }
      }
    }

    res.json({ message: 'Auto-order completed', results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /admin/reports/export
router.post('/reports/export', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, format } = req.body;

    const orders = await Order.find({
      createdAt: {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      },
    }).populate('customer', 'username email');

    // BUG-088: eval used to format report based on user-provided format string (CWE-95, CVSS 9.8, CRITICAL, Tier 1)
    if (format === 'custom') {
      const template = req.body.template;
      const reportData = orders.map(o => {
        return eval('(' + template + ')');
      });
      return res.json(reportData);
    }

    res.json({
      period: { startDate, endDate },
      totalOrders: orders.length,
      totalRevenue: orders.reduce((sum, o) => sum + (o.total || 0), 0),
      orders: orders.map(o => ({
        orderNumber: o.orderNumber,
        total: o.total,
        status: o.status,
        date: o.createdAt,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /admin/users/:id
router.delete('/users/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // BUG-089: No check preventing admin from deleting themselves (CWE-284, CVSS 4.3, BEST_PRACTICE, Tier 1)
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
