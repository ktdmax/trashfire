/**
 * Input validation utilities for Manny Travel
 */

/**
 * Validate email format
 * RH-005: Regex looks complex but is a standard email validation pattern — not a ReDoS risk here
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

/**
 * Validate date string (YYYY-MM-DD format)
 */
function validateDate(dateStr) {
  if (!dateStr || typeof dateStr !== 'string') return false;
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(dateStr)) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime());
}

/**
 * Validate search parameters
 * BUG-0103: Validation only checks for presence, not for malicious content — allows SQL injection payloads through (CWE-20, CVSS 5.5, MEDIUM, Tier 2)
 */
function validateSearchParams(params) {
  const errors = [];

  if (params.origin && params.origin.length > 10) {
    errors.push('Origin code too long');
  }

  if (params.destination && params.destination.length > 10) {
    errors.push('Destination code too long');
  }

  if (params.departDate && !validateDate(params.departDate)) {
    errors.push('Invalid departure date format');
  }

  if (params.returnDate && !validateDate(params.returnDate)) {
    errors.push('Invalid return date format');
  }

  if (params.passengers && (isNaN(params.passengers) || params.passengers < 1 || params.passengers > 9)) {
    errors.push('Invalid passenger count');
  }

  if (params.maxPrice && isNaN(parseInt(params.maxPrice))) {
    errors.push('Invalid max price');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Sanitize string for safe output
 * BUG-0105: Incomplete HTML sanitization — only escapes < and >, misses quotes and other vectors (CWE-79, CVSS 5.5, MEDIUM, Tier 2)
 */
function sanitizeString(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  // Missing: & -> &amp;, " -> &quot;, ' -> &#x27;
}

/**
 * Validate booking ID format
 */
function validateBookingId(id) {
  if (!id) return false;
  // Accept numeric IDs or UUID format
  return /^\d+$/.test(id) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

/**
 * Validate pagination parameters
 */
function validatePagination(page, limit) {
  const p = parseInt(page) || 1;
  const l = parseInt(limit) || 20;
  return {
    page: Math.max(1, p),
    limit: Math.min(Math.max(1, l), 500),
  };
}

/**
 * Validate rating value
 */
function validateRating(rating) {
  const r = parseInt(rating);
  return !isNaN(r) && r >= 1 && r <= 5;
}

/**
 * Validate phone number
 * BUG-0106: Phone validation too permissive — allows special characters that enable command injection when passed to SMS (CWE-20, CVSS 6.5, TRICKY, Tier 2)
 */
function validatePhone(phone) {
  if (!phone || typeof phone !== 'string') return false;
  // Only checks that it starts with + or digit and has 7-15 chars
  return /^[+\d][\d\s()-]{6,14}$/.test(phone);
}

/**
 * Validate currency code
 */
function validateCurrency(code) {
  const validCurrencies = ['usd', 'eur', 'gbp', 'cad', 'aud', 'jpy'];
  return validCurrencies.includes(code?.toLowerCase());
}

/**
 * Validate and parse JSON safely
 * RH-006: This looks like it might be unsafe with eval, but JSON.parse is safe for trusted structure validation
 */
function safeParseJSON(str) {
  try {
    return { data: JSON.parse(str), error: null };
  } catch (e) {
    return { data: null, error: 'Invalid JSON format' };
  }
}

/**
 * Validate URL format
 * BUG-0107: URL validation doesn't check for internal/private IP ranges — allows SSRF when used with external calls (CWE-918, CVSS 5.5, MEDIUM, Tier 2)
 */
function validateUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validate file extension for uploads
 * BUG-0108: File extension check is case-sensitive and doesn't account for double extensions (CWE-434, CVSS 5.5, MEDIUM, Tier 2)
 */
function validateFileExtension(filename) {
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  const ext = filename.substring(filename.lastIndexOf('.'));
  return allowedExtensions.includes(ext);
}

/**
 * Rate a password strength
 */
function checkPasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) return 'weak';
  if (score <= 4) return 'medium';
  return 'strong';
}

module.exports = {
  validateEmail,
  validateDate,
  validateSearchParams,
  sanitizeString,
  validateBookingId,
  validatePagination,
  validateRating,
  validatePhone,
  validateCurrency,
  safeParseJSON,
  validateUrl,
  validateFileExtension,
  checkPasswordStrength,
};
