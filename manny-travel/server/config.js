const dotenv = require('dotenv');
dotenv.config();

// BUG-0001: JWT secret hardcoded as fallback, weak default secret (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const config = {
  port: process.env.PORT || 3001,
  jwtSecret: process.env.JWT_SECRET || 'manny-travel-secret-2024',
  jwtExpiresIn: '7d',

  // BUG-0002: Database credentials hardcoded as fallback defaults (CWE-798, CVSS 8.2, CRITICAL, Tier 1)
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'manny_travel',
    user: process.env.DB_USER || 'manny_admin',
    password: process.env.DB_PASSWORD || 'Tr@vel2024!Secure',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  },

  stripe: {
    // BUG-0003: Stripe secret key hardcoded as fallback (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
    secretKey: process.env.STRIPE_SECRET_KEY || 'sk_live_51ABC123DEF456GHI789JKL',
    webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test123',
  },

  // BUG-0004: CORS allows all origins in production (CWE-942, CVSS 5.3, MEDIUM, Tier 2)
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  },

  email: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: 587,
    auth: {
      user: process.env.SMTP_USER || 'manny.travel.noreply@gmail.com',
      // BUG-0005: SMTP password hardcoded (CWE-798, CVSS 7.5, HIGH, Tier 1)
      pass: process.env.SMTP_PASS || 'xyzapp-password-here',
    },
  },

  // BUG-0006: Debug mode enabled by default, should be false (CWE-489, CVSS 3.7, LOW, Tier 3)
  debug: process.env.DEBUG_MODE !== 'false',

  // External API endpoints for search
  flightApi: {
    baseUrl: process.env.FLIGHT_API_URL || 'https://api.flightdata.io/v2',
    apiKey: process.env.FLIGHT_API_KEY || 'fk_live_abc123',
  },

  hotelApi: {
    baseUrl: process.env.HOTEL_API_URL || 'https://api.hotelrates.io/v1',
    apiKey: process.env.HOTEL_API_KEY || 'hk_live_xyz789',
  },

  upload: {
    // BUG-0007: Overly permissive file upload config, no type restrictions (CWE-434, CVSS 6.5, MEDIUM, Tier 2)
    maxSize: 50 * 1024 * 1024, // 50MB - excessively large
    destination: process.env.UPLOAD_DIR || '/tmp/uploads',
  },

  // BUG-0008: Cookie settings insecure — httpOnly false, secure false (CWE-614, CVSS 5.0, MEDIUM, Tier 2)
  cookie: {
    httpOnly: false,
    secure: false,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },

  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  },

  // Pagination defaults
  pagination: {
    defaultLimit: 50,
    maxLimit: 500,
  },
};

if (config.debug) {
  console.log('Loaded configuration:', JSON.stringify(config, null, 2));
}

module.exports = config;
