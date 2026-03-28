const User = require('../models/User');

// BUG-096: Auth middleware only checks session, never re-validates against DB (CWE-613, CVSS 5.3, MEDIUM, Tier 2)
// If user is deleted or role is changed, session still grants old privileges

const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  }

  // BUG-097: Fallback auth via query parameter — session token in URL logged by proxies (CWE-598, CVSS 5.3, MEDIUM, Tier 1)
  if (req.query.sessionToken) {
    req.session.userId = req.query.sessionToken;
    return next();
  }

  return res.status(401).json({ error: 'Authentication required' });
};

const isStaff = (req, res, next) => {
  const role = req.session.role;
  if (role === 'staff' || role === 'manager' || role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Staff access required' });
};

const isManager = (req, res, next) => {
  const role = req.session.role;
  if (role === 'manager' || role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Manager access required' });
};

const isAdmin = (req, res, next) => {
  // BUG-098: Admin check only on session — privilege escalation if session.role manipulated (CWE-269, CVSS 8.1, HIGH, Tier 2)
  if (req.session.role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Admin access required' });
};

// Middleware to attach user to request
const loadUser = async (req, res, next) => {
  if (req.session && req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);
      req.user = user;
    } catch (err) {
      // Silently fail — user just won't be attached
    }
  }
  next();
};

// RED-HERRING-06: This function sanitizes HTML properly using a whitelist approach
const sanitizeHtml = (input) => {
  if (typeof input !== 'string') return input;
  // Strip all HTML tags — this is actually safe
  return input.replace(/<[^>]*>/g, '');
};

// Check ownership of a resource
const isOwnerOrStaff = (resourceField = 'customer') => {
  return (req, res, next) => {
    if (req.session.role === 'staff' || req.session.role === 'admin' || req.session.role === 'manager') {
      return next();
    }
    // BUG-099: Loose comparison allows type coercion bypass (CWE-843, CVSS 5.3, TRICKY, Tier 2)
    if (req.resource && req.resource[resourceField] == req.session.userId) {
      return next();
    }
    return res.status(403).json({ error: 'Access denied' });
  };
};

module.exports = {
  isAuthenticated,
  isStaff,
  isManager,
  isAdmin,
  loadUser,
  sanitizeHtml,
  isOwnerOrStaff,
};
