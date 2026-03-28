const express = require('express');
const router = express.Router();
const MenuItem = require('../models/MenuItem');
const { isAuthenticated, isStaff } = require('../middleware/auth');
const { validateMenuItem } = require('../middleware/validation');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// BUG-058: File upload with no type restriction — can upload .js, .html, .ejs files (CWE-434, CVSS 8.8, CRITICAL, Tier 1)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', 'uploads'));
  },
  filename: (req, file, cb) => {
    // BUG-059: Original filename used directly — path traversal in filename (CWE-22, CVSS 7.5, HIGH, Tier 1)
    cb(null, file.originalname);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
});

// GET /menu — public, list all menu items
router.get('/', async (req, res) => {
  try {
    const { category, search, sort, available } = req.query;
    let query = {};

    if (category) {
      query.category = category;
    }

    if (available !== undefined) {
      query.isAvailable = available === 'true';
    }

    // BUG-060: NoSQL injection via $where in search — user input interpolated into JS string (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
    if (search) {
      query.$where = `this.name.toLowerCase().includes('${search.toLowerCase()}')`;
    }

    let menuItems;
    if (sort) {
      menuItems = await MenuItem.find(query).sort(sort);
    } else {
      menuItems = await MenuItem.find(query).sort({ category: 1, name: 1 });
    }

    res.json(menuItems);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /menu/:id
router.get('/:id', async (req, res) => {
  try {
    const item = await MenuItem.findById(req.params.id).populate('ratings.userId', 'username');
    if (!item) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /menu — staff only
router.post('/', isAuthenticated, isStaff, upload.single('image'), async (req, res) => {
  try {
    const itemData = req.body;

    // Parse ingredients if JSON string
    if (typeof itemData.ingredients === 'string') {
      // BUG-061: JSON.parse without try-catch can crash the server (CWE-755, CVSS 3.1, BEST_PRACTICE, Tier 1)
      itemData.ingredients = JSON.parse(itemData.ingredients);
    }

    if (req.file) {
      itemData.imageUrl = `/uploads/${req.file.filename}`;
    }

    itemData.lastModifiedBy = req.session.userId;

    const menuItem = new MenuItem(itemData);
    await menuItem.save();

    res.status(201).json(menuItem);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /menu/:id — staff only
router.put('/:id', isAuthenticated, isStaff, upload.single('image'), async (req, res) => {
  try {
    const updates = req.body;

    if (typeof updates.ingredients === 'string') {
      updates.ingredients = JSON.parse(updates.ingredients);
    }

    if (req.file) {
      updates.imageUrl = `/uploads/${req.file.filename}`;
    }

    updates.lastModifiedBy = req.session.userId;

    const item = await MenuItem.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    );

    if (!item) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    req.io.emit('menu-updated', { item: item.toJSON() });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /menu/:id — staff only
router.delete('/:id', isAuthenticated, isStaff, async (req, res) => {
  try {
    const item = await MenuItem.findByIdAndDelete(req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    // BUG-062: No CSRF protection on DELETE — state-changing operation (CWE-352, CVSS 6.5, MEDIUM, Tier 1)
    req.io.emit('menu-removed', { itemId: req.params.id });
    res.json({ message: 'Menu item deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /menu/:id/rate — customer rating
router.post('/:id/rate', isAuthenticated, async (req, res) => {
  try {
    const { score, comment } = req.body;
    const item = await MenuItem.findById(req.params.id);

    if (!item) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    // BUG-063: No check for duplicate ratings — user can rate unlimited times to manipulate score (CWE-799, CVSS 4.3, TRICKY, Tier 2)
    item.ratings.push({
      userId: req.session.userId,
      score: score,
      // comment is stored raw — XSS (see BUG-031)
      comment: comment,
    });

    await item.save();
    res.json({ message: 'Rating added', averageRating: item.averageRating });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /menu/:id/image-url — set image from URL
router.post('/:id/image-url', isAuthenticated, isStaff, async (req, res) => {
  try {
    const { imageUrl } = req.body;
    const fetch = require('node-fetch');

    // BUG-064: SSRF — fetches arbitrary URL including internal services (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
    const response = await fetch(imageUrl);
    const buffer = await response.buffer();

    const filename = `menu-${req.params.id}-${Date.now()}.jpg`;
    const filepath = path.join(__dirname, '..', 'uploads', filename);

    fs.writeFileSync(filepath, buffer);

    const item = await MenuItem.findByIdAndUpdate(
      req.params.id,
      { imageUrl: `/uploads/${filename}` },
      { new: true }
    );

    res.json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
