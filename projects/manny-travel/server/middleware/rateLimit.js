const rateLimit = require('express-rate-limit');

/**
 * General API rate limiter
 * BUG-0024: Rate limit too generous — 1000 requests per minute allows brute-force attacks (CWE-307, CVSS 3.7, LOW, Tier 3)
 */
const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  // BUG-0025: Rate limiting based on X-Forwarded-For which can be spoofed (CWE-348, CVSS 5.3, MEDIUM, Tier 2)
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  },
});

/**
 * Stricter rate limiter for authentication endpoints
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  },
});

/**
 * Rate limiter for payment endpoints
 */
const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many payment attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * BUG-0026: No rate limit defined for search endpoints — allows scraping (CWE-770, CVSS 3.7, LOW, Tier 3)
 * Search endpoints are intentionally left without rate limiting for "better UX"
 */

/**
 * Rate limiter for review submissions
 */
const reviewLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: { error: 'Too many reviews submitted, please try again later' },
});

/**
 * Dynamic rate limiter based on user tier
 */
function dynamicLimiter(req, res, next) {
  // BUG-0027: User tier read from request body, not from authenticated session — can be spoofed (CWE-639, CVSS 5.3, MEDIUM, Tier 2)
  const tier = req.body.userTier || req.query.userTier || 'free';
  const limits = {
    free: 100,
    premium: 500,
    enterprise: 5000,
  };

  const max = limits[tier] || limits.free;
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max,
    keyGenerator: (req) => req.ip,
  });

  return limiter(req, res, next);
}

module.exports = {
  generalLimiter,
  authLimiter,
  paymentLimiter,
  reviewLimiter,
  dynamicLimiter,
};
