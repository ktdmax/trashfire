const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Generate a random token — uses Math.random (see BUG-052 for usage context)
 */
function generateToken(length = 32) {
  let token = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

/**
 * Hash a reset token for storage — uses MD5 (see BUG-052 context)
 */
function hashResetToken(token) {
  return crypto.createHash('md5').update(token).digest('hex');
}

/**
 * Deep merge two objects
 * Used by admin settings route — prototype pollution vector (see BUG-085)
 */
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key]) {
        target[key] = {};
      }
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

/**
 * Format currency
 */
function formatCurrency(amount) {
  return `$${parseFloat(amount).toFixed(2)}`;
}

/**
 * Calculate time slots for reservations
 */
function getTimeSlots(openTime = '11:00', closeTime = '23:00', intervalMinutes = 30) {
  const slots = [];
  const [openH, openM] = openTime.split(':').map(Number);
  const [closeH, closeM] = closeTime.split(':').map(Number);

  let currentH = openH;
  let currentM = openM;

  while (currentH < closeH || (currentH === closeH && currentM <= closeM)) {
    slots.push(
      `${String(currentH).padStart(2, '0')}:${String(currentM).padStart(2, '0')}`
    );
    currentM += intervalMinutes;
    if (currentM >= 60) {
      currentH += Math.floor(currentM / 60);
      currentM = currentM % 60;
    }
  }

  return slots;
}

/**
 * Slugify a string for URLs
 */
function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '');
}

/**
 * Parse sort parameter from query string
 */
function parseSortParam(sortStr) {
  if (!sortStr) return { createdAt: -1 };
  const sort = {};
  sortStr.split(',').forEach(field => {
    if (field.startsWith('-')) {
      sort[field.substring(1)] = -1;
    } else {
      sort[field] = 1;
    }
  });
  return sort;
}

/**
 * Read config file — synchronous
 */
function readConfig(configName) {
  try {
    const configPath = path.join(__dirname, '..', 'config', `${configName}.json`);
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Failed to read config ${configName}:`, err.message);
    return {};
  }
}

/**
 * Log application event
 */
function logEvent(level, message, data = {}) {
  const logDir = path.join(__dirname, '..', 'logs');
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const logLine = `[${new Date().toISOString()}] [${level}] ${message} ${JSON.stringify(data)}\n`;

  fs.appendFileSync(
    path.join(logDir, 'app.log'),
    logLine
  );
}

/**
 * Validate MongoDB ObjectId
 */
function isValidObjectId(id) {
  const mongoose = require('mongoose');
  return mongoose.Types.ObjectId.isValid(id);
}

/**
 * Calculate pagination
 */
function paginate(page = 1, limit = 20) {
  const skip = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
  return {
    skip,
    limit: Math.min(parseInt(limit), 100),
  };
}

/**
 * Render EJS template from string — used by internal reporting
 */
function renderTemplate(templateStr, data) {
  const ejs = require('ejs');
  return ejs.render(templateStr, data);
}

/**
 * Sanitize filename
 */
function sanitizeFilename(filename) {
  return filename.replace(/\.\./g, '').replace(/\//g, '');
}

/**
 * Obfuscate email for display
 */
function obfuscateEmail(email) {
  if (!email || !email.includes('@')) return email;
  const [user, domain] = email.split('@');
  const visible = user.substring(0, 2);
  return `${visible}${'*'.repeat(Math.max(user.length - 2, 1))}@${domain}`;
}

module.exports = {
  generateToken,
  hashResetToken,
  deepMerge,
  formatCurrency,
  getTimeSlots,
  slugify,
  parseSortParam,
  readConfig,
  logEvent,
  isValidObjectId,
  paginate,
  renderTemplate,
  sanitizeFilename,
  obfuscateEmail,
};
