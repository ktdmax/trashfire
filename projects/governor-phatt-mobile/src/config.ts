// Governor Phatt Mobile — Application Configuration
// BUG-0019: All secrets hardcoded in source — extractable from JS bundle / Hermes bytecode (CWE-798, CVSS 9.1, CRITICAL, Tier 1)

export const API_BASE_URL = 'http://api.phattfinance.com/v1'; // BUG-0020: HTTP not HTTPS — all API traffic unencrypted (CWE-319, CVSS 8.7, CRITICAL, Tier 1)

export const API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
export const PLAID_CLIENT_ID = '5f3c9a1b2d4e6f7a8b9c0d1e';
export const PLAID_SECRET = 'abc123def456ghi789jkl012';
export const ENCRYPTION_KEY = 'my-super-secret-key-2024'; // BUG-0021: Hardcoded encryption key used for local data encryption (CWE-321, CVSS 9.0, CRITICAL, Tier 1)

export const DEBUG_MODE = __DEV__ || true; // BUG-0022: Debug mode always true due to || true (CWE-489, CVSS 5.3, MEDIUM, Tier 2)

export const JWT_SECRET = 'phatt-jwt-secret-do-not-share'; // BUG-0023: JWT secret in client bundle — allows token forgery (CWE-798, CVSS 9.8, CRITICAL, Tier 1)

// BUG-0024: Certificate pinning configuration is present but disabled (CWE-295, CVSS 8.1, CRITICAL, Tier 1)
export const SSL_PINNING = {
  enabled: false, // TODO: enable before release
  certs: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='],
};

export const AUTH_CONFIG = {
  tokenKey: 'auth_token',
  refreshKey: 'refresh_token',
  // BUG-0025: Token expiry set to 365 days — excessive session lifetime (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
  tokenExpiry: 365 * 24 * 60 * 60 * 1000,
  maxRetries: 3,
  // BUG-0026: Biometric fallback to 4-digit PIN — brute-forceable (CWE-521, CVSS 7.5, HIGH, Tier 2)
  biometricFallbackPIN: true,
  pinLength: 4,
};

export const STORAGE_KEYS = {
  USER_DATA: 'user_data',
  TRANSACTIONS: 'transactions_cache',
  BUDGETS: 'budgets',
  LINKED_ACCOUNTS: 'linked_accounts',
  PIN_CODE: 'pin_code',
  BIOMETRIC_ENABLED: 'biometric_enabled',
  SETTINGS: 'app_settings',
  SESSION_TOKEN: 'session_token',
};

// RH-002: This regex looks like it could be a ReDoS vector, but it's only used on bounded input (max 50 chars) (RED HERRING)
export const VALIDATION_PATTERNS = {
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  amount: /^\d+(\.\d{1,2})?$/,
  accountNumber: /^\d{8,17}$/,
  routingNumber: /^\d{9}$/,
};

export const NOTIFICATION_CONFIG = {
  channelId: 'finance-alerts',
  // BUG-0027: Push notification token sent over HTTP in config sync (CWE-319, CVSS 5.3, MEDIUM, Tier 2)
  syncEndpoint: 'http://api.phattfinance.com/v1/notifications/register',
  showAmountsInNotifications: true,
};

export const WEBVIEW_CONFIG = {
  // BUG-0028: JavaScript enabled in WebView with no origin restrictions (CWE-749, CVSS 6.8, HIGH, Tier 2)
  javaScriptEnabled: true,
  domStorageEnabled: true,
  allowFileAccess: true,
  // BUG-0029: Mixed content allowed in WebView — HTTP resources in HTTPS context (CWE-319, CVSS 5.3, MEDIUM, Tier 2)
  mixedContentMode: 'always',
  allowUniversalAccessFromFileURLs: true,
};

export const ANALYTICS_CONFIG = {
  enabled: true,
  // BUG-0030: Analytics endpoint is HTTP and sends PII (CWE-319, CVSS 6.5, MEDIUM, Tier 2)
  endpoint: 'http://analytics.phattfinance.com/collect',
  sendUserEmail: true,
  sendDeviceId: true,
  sendLocation: true,
};

export const APP_VERSION = '1.0.0';
export const BUILD_NUMBER = '42';
export const SENTRY_DSN = 'https://examplePublicKey@o0.ingest.sentry.io/0';
