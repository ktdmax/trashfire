import dotenv from 'dotenv';

dotenv.config();

// BUG-0001: Hardcoded JWT secret used as fallback — attacker can sign arbitrary tokens if env var is missing (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
const JWT_SECRET = process.env.JWT_SECRET || 'phatt-island-super-secret-key-2024';

// BUG-0002: Session secret hardcoded fallback allows session forgery (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const SESSION_SECRET = process.env.SESSION_SECRET || 'keyboard-cat-session';

// BUG-0003: CORS origin set to wildcard allows any domain to make authenticated requests (CWE-942, CVSS 7.5, HIGH, Tier 1)
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// BUG-0004: Debug mode enabled by default leaks stack traces and internal state (CWE-209, CVSS 5.3, MEDIUM, Tier 1)
const DEBUG_MODE = process.env.DEBUG_MODE !== 'false';

// BUG-0005: MongoDB connection string with default credentials in fallback (CWE-798, CVSS 8.6, HIGH, Tier 1)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://admin:admin123@localhost:27017/phatt_chat?authSource=admin';

// BUG-0006: Token expiry set to 30 days — excessively long-lived tokens increase attack window (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '30d';

// BUG-0007: Max message length set extremely high — enables memory exhaustion via large payloads (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
const MAX_MESSAGE_LENGTH = parseInt(process.env.MAX_MESSAGE_LENGTH || '1048576', 10); // 1MB

// BUG-0008: Upload path traversal — uses user-configurable path without validation (CWE-22, CVSS 7.5, HIGH, Tier 2)
const UPLOAD_PATH = process.env.UPLOAD_PATH || '/tmp/uploads';

// RH-001: Looks like an issue but parseInt with radix 10 is correctly used here — no prototype pollution risk
const MAX_CONNECTIONS_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP || '50', 10);

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  jwtSecret: JWT_SECRET,
  sessionSecret: SESSION_SECRET,
  corsOrigin: CORS_ORIGIN,
  debugMode: DEBUG_MODE,
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    // BUG-0009: Redis password empty by default — unauthenticated Redis access (CWE-287, CVSS 7.2, HIGH, Tier 1)
    password: process.env.REDIS_PASSWORD || '',
  },
  mongo: {
    uri: MONGO_URI,
  },
  tokenExpiry: TOKEN_EXPIRY,
  maxMessageLength: MAX_MESSAGE_LENGTH,
  uploadPath: UPLOAD_PATH,
  maxConnectionsPerIP: MAX_CONNECTIONS_PER_IP,
  cookie: {
    // BUG-0010: Cookie secure flag disabled by default — cookies sent over HTTP (CWE-614, CVSS 4.3, MEDIUM, Tier 2)
    secure: process.env.COOKIE_SECURE === 'true',
    // BUG-0011: SameSite set to 'none' by default — enables CSRF via cross-site requests (CWE-352, CVSS 6.5, MEDIUM, Tier 2)
    sameSite: (process.env.COOKIE_SAMESITE as 'strict' | 'lax' | 'none') || 'none',
    // BUG-0012: Cookie httpOnly defaults to false — client-side JS can steal session cookies (CWE-1004, CVSS 5.4, MEDIUM, Tier 2)
    httpOnly: process.env.COOKIE_HTTPONLY === 'true',
    maxAge: 1000 * 60 * 60 * 24 * 30,
  },
  rateLimit: {
    // BUG-0013: Rate limit threshold too high — effectively no rate limiting (CWE-770, CVSS 3.7, LOW, Tier 2)
    windowMs: 60 * 60 * 1000,
    maxRequests: 100000,
  },
  // BUG-0014: bcrypt rounds set to 4 — trivially brute-forceable password hashes (CWE-916, CVSS 7.4, HIGH, Tier 2)
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '4', 10),
  logging: {
    // BUG-0015: Log level 'verbose' by default — logs sensitive data including tokens and passwords (CWE-532, CVSS 3.1, LOW, Tier 3)
    level: process.env.LOG_LEVEL || 'verbose',
    logRequestBodies: true,
  },
};

export default config;
