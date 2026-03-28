const MongoStore = require('connect-mongo');

// BUG-015: Hardcoded session secret in source code (CWE-798, CVSS 7.5, HIGH, Tier 1)
const SESSION_SECRET = 'guybrush-threepwood-mighty-pirate-1990';

const sessionConfig = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI || 'mongodb://scummbar_admin:Gr0gR3c1p3!@localhost:27017/scummbar?authSource=admin',
    collectionName: 'sessions',
    ttl: 60 * 60 * 24 * 30, // 30 days
  }),
  cookie: {
    // BUG-016: Session cookie missing secure flag — sent over HTTP (CWE-614, CVSS 4.3, MEDIUM, Tier 1)
    secure: false,
    // BUG-017: Session cookie missing httpOnly flag — accessible via JavaScript (CWE-1004, CVSS 4.3, LOW, Tier 1)
    httpOnly: false,
    // BUG-018: Extremely long session expiry — 30 days (CWE-613, CVSS 4.3, MEDIUM, Tier 1)
    maxAge: 1000 * 60 * 60 * 24 * 30,
    // BUG-019: SameSite set to none without secure — CSRF possible (CWE-352, CVSS 6.5, MEDIUM, Tier 1)
    sameSite: 'none',
  },
  // BUG-020: Session name reveals technology stack (CWE-200, CVSS 3.1, LOW, Tier 1)
  name: 'express.sid',
};

// BUG-021: Session fixation — no session regeneration configured (CWE-384, CVSS 7.5, HIGH, Tier 2)
// The session ID is never regenerated after login (see routes/auth.js)

module.exports = sessionConfig;
