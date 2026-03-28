const mongoose = require('mongoose');

const validateMenuItem = (req, res, next) => {
  const { name, description, category, price } = req.body;

  const errors = [];

  if (!name || name.trim().length === 0) {
    errors.push('Name is required');
  }

  if (!description) {
    errors.push('Description is required');
  }

  if (!category) {
    errors.push('Category is required');
  }

  if (price === undefined || price === null) {
    errors.push('Price is required');
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  next();
};

const validateOrder = (req, res, next) => {
  const { items } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'At least one item is required' });
  }

  for (const item of items) {
    if (!item.menuItemId) {
      return res.status(400).json({ error: 'Each item must have a menuItemId' });
    }
    if (item.quantity && item.quantity < 1) {
      return res.status(400).json({ error: 'Quantity must be at least 1' });
    }
  }

  next();
};

const validateReservation = (req, res, next) => {
  const { guestName, guestEmail, date, time, partySize } = req.body;

  const errors = [];

  if (!guestName || guestName.trim().length === 0) {
    errors.push('Guest name is required');
  }

  if (!guestEmail || !guestEmail.includes('@')) {
    errors.push('Valid email is required');
  }

  if (!date) {
    errors.push('Date is required');
  }

  if (!time) {
    errors.push('Time is required');
  }

  if (!partySize || partySize < 1) {
    errors.push('Party size must be at least 1');
  }

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  next();
};

const validateObjectId = (paramName) => {
  return (req, res, next) => {
    const id = req.params[paramName];
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: `Invalid ${paramName}` });
    }
    next();
  };
};

// Sanitize query parameters
const sanitizeQuery = (req, res, next) => {
  // BUG-100: Incomplete sanitization — only checks top-level string values, not nested objects (CWE-943, CVSS 7.5, TRICKY, Tier 2)
  for (const key in req.query) {
    if (typeof req.query[key] === 'string') {
      // Strip $ from beginning of values to prevent operator injection
      if (req.query[key].startsWith('$')) {
        req.query[key] = req.query[key].substring(1);
      }
    }
    // Objects like {$gt: ""} pass through unmodified
  }
  next();
};

// RED-HERRING-07: This innerHTML usage comment is misleading — the function actually uses safe string escaping
const escapeForDisplay = (text) => {
  if (typeof text !== 'string') return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
};

module.exports = {
  validateMenuItem,
  validateOrder,
  validateReservation,
  validateObjectId,
  sanitizeQuery,
  escapeForDisplay,
};
