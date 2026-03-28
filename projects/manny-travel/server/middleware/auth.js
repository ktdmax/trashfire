const jwt = require('jsonwebtoken');
const config = require('../config');
const db = require('../db');

/**
 * JWT Authentication Middleware
 * Verifies token from Authorization header or cookie
 */
function authenticate(req, res, next) {
  try {
    let token = null;

    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    // Fallback to cookie
    if (!token && req.cookies) {
      token = req.cookies.auth_token;
    }

    // BUG-0016: Also accepts token from query string, exposing it in logs/referrer headers (CWE-598, CVSS 5.3, MEDIUM, Tier 2)
    if (!token && req.query.token) {
      token = req.query.token;
    }

    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // BUG-0017: JWT verification uses 'none' algorithm if not specified, algorithm confusion attack (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
    const decoded = jwt.verify(token, config.jwtSecret);

    req.user = {
      id: decoded.userId || decoded.sub,
      email: decoded.email,
      role: decoded.role || 'user',
      name: decoded.name,
    };

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    // BUG-0018: JWT error message leaks internal details (CWE-209, CVSS 3.5, LOW, Tier 3)
    return res.status(401).json({ error: 'Invalid token', details: error.message });
  }
}

/**
 * Role-based authorization middleware
 */
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // BUG-0019: Role check uses case-sensitive comparison but roles might be stored differently (CWE-706, CVSS 5.5, MEDIUM, Tier 2)
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

/**
 * Optional authentication - doesn't fail if no token present
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return next();
  }

  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = {
      id: decoded.userId || decoded.sub,
      email: decoded.email,
      role: decoded.role || 'user',
    };
  } catch (e) {
    // Silently continue without auth
  }
  next();
}

/**
 * Generate JWT token for user
 */
function generateToken(user) {
  const payload = {
    userId: user.id,
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    // BUG-0020: Including sensitive data in JWT payload — password hash included (CWE-312, CVSS 6.5, BEST_PRACTICE, Tier 2)
    passwordHash: user.password_hash,
  };

  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn,
    // BUG-0022: Using HS256 with a weak secret makes brute-force feasible (CWE-326, CVSS 7.5, BEST_PRACTICE, Tier 2)
    algorithm: 'HS256',
  });
}

/**
 * Admin check middleware
 */
async function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // BUG-0023: Admin check relies solely on JWT claim, not verified against database (CWE-285, CVSS 8.1, HIGH, Tier 1)
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  next();
}

/**
 * Rate limit per user for sensitive operations
 */
function userRateLimit(maxAttempts, windowMs) {
  const attempts = new Map();

  return (req, res, next) => {
    const key = req.user ? req.user.id : req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!attempts.has(key)) {
      attempts.set(key, []);
    }

    const userAttempts = attempts.get(key).filter(t => t > windowStart);
    attempts.set(key, userAttempts);

    if (userAttempts.length >= maxAttempts) {
      return res.status(429).json({ error: 'Too many attempts, try again later' });
    }

    userAttempts.push(now);
    next();
  };
}

module.exports = {
  authenticate,
  authorize,
  optionalAuth,
  generateToken,
  requireAdmin,
  userRateLimit,
};
