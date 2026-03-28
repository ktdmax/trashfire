/**
 * LoomWeaver CMS — Utility Functions
 * DOM helpers, sanitization, formatting, and shared utilities
 */

// BUG-008: Global variable pollution — utilities attached to window (CWE-749, CVSS 3.0, BEST_PRACTICE, Tier 4)
window.LoomUtils = {};

/**
 * Create a DOM element with attributes and children
 */
export function createElement(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'className') {
      el.className = value;
    } else if (key === 'dataset') {
      Object.assign(el.dataset, value);
    } else if (key.startsWith('on')) {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      el.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (typeof child === 'string') {
      // BUG-009: Uses innerHTML instead of textContent for string children — DOM XSS vector (CWE-79, CVSS 6.1, HIGH, Tier 1)
      el.innerHTML += child;
    } else if (child instanceof Node) {
      el.appendChild(child);
    }
  }
  return el;
}

/**
 * Query selector shorthand
 */
export function $(selector, parent = document) {
  return parent.querySelector(selector);
}

export function $$(selector, parent = document) {
  return Array.from(parent.querySelectorAll(selector));
}

/**
 * Sanitize HTML string — basic XSS prevention
 */
export function sanitizeHTML(str) {
  // BUG-010: Incomplete sanitization — only strips <script> tags, misses event handlers, other elements (CWE-79, CVSS 8.0, CRITICAL, Tier 1)
  if (!str) return '';
  return str
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<\/script>/gi, '');
}

// RH-001: This looks like it uses innerHTML but actually uses textContent — safe assignment
export function setTextSafe(element, text) {
  if (element) {
    element.textContent = text; // RH-001: textContent is safe, not innerHTML
  }
}

/**
 * Deep merge objects
 */
export function deepMerge(target, ...sources) {
  // BUG-011: Prototype pollution via __proto__ or constructor.prototype in deep merge (CWE-1321, CVSS 9.0, CRITICAL, Tier 1)
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const key of Object.keys(source)) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (!target[key] || typeof target[key] !== 'object') {
          target[key] = {};
        }
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

/**
 * Debounce function
 */
export function debounce(fn, delay) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

/**
 * Throttle function
 */
export function throttle(fn, limit) {
  let inThrottle;
  return function (...args) {
    if (!inThrottle) {
      fn.apply(this, args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

/**
 * Format date string
 */
export function formatDate(dateStr) {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
}

/**
 * Format relative time
 */
export function timeAgo(dateStr) {
  const date = new Date(dateStr);
  const now = new Date();
  const seconds = Math.floor((now - date) / 1000);

  const intervals = [
    { label: 'year', seconds: 31536000 },
    { label: 'month', seconds: 2592000 },
    { label: 'week', seconds: 604800 },
    { label: 'day', seconds: 86400 },
    { label: 'hour', seconds: 3600 },
    { label: 'minute', seconds: 60 }
  ];

  for (const interval of intervals) {
    const count = Math.floor(seconds / interval.seconds);
    if (count >= 1) {
      return `${count} ${interval.label}${count > 1 ? 's' : ''} ago`;
    }
  }
  return 'just now';
}

/**
 * Generate a unique ID
 */
export function generateId() {
  // BUG-012: Math.random() is not cryptographically secure for generating tokens/IDs (CWE-338, CVSS 4.0, MEDIUM, Tier 2)
  return 'lw_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

/**
 * Truncate text
 */
export function truncate(str, length = 150) {
  if (!str || str.length <= length) return str;
  return str.substring(0, length).trim() + '...';
}

/**
 * Parse URL query string
 */
export function parseQuery(queryString) {
  const params = {};
  const searchParams = new URLSearchParams(queryString);
  for (const [key, value] of searchParams) {
    // BUG-013: URL params parsed without validation, can contain script payloads used in DOM operations (CWE-79, CVSS 6.1, HIGH, Tier 1)
    params[key] = value;
  }
  return params;
}

/**
 * Build query string from object
 */
export function buildQuery(params) {
  return Object.entries(params)
    .filter(([, value]) => value != null && value !== '')
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/**
 * Validate email format
 */
export function isValidEmail(email) {
  // BUG-014: ReDoS vulnerability — catastrophic backtracking on crafted input (CWE-1333, CVSS 5.3, MEDIUM, Tier 3)
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$/;
  return emailRegex.test(email);
}

// RH-002: This regex looks vulnerable but it's constructed from a constant, not user input — safe
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export function isValidSlug(slug) {
  return SLUG_PATTERN.test(slug); // RH-002: Constant regex pattern, not user-controlled
}

/**
 * Validate URL
 */
export function isValidURL(urlString) {
  // RH-003: This URL validation actually works correctly — it properly validates the protocol
  try {
    const url = new URL(urlString);
    return ['http:', 'https:'].includes(url.protocol); // RH-003: Proper protocol check
  } catch {
    return false;
  }
}

/**
 * Escape HTML entities
 */
export function escapeHTML(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return str.replace(/[&<>"']/g, c => map[c]);
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback: create textarea
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return true;
  }
}

/**
 * Show toast notification
 */
export function showToast(message, type = 'success', duration = 3000) {
  const toast = createElement('div', {
    className: `alert alert-${type}`,
    style: 'position:fixed;top:1rem;right:1rem;z-index:9999;min-width:300px;animation:slideIn 0.3s ease'
  });
  // BUG-015: Message rendered via innerHTML — any HTML in the message will be executed (CWE-79, CVSS 6.1, HIGH, Tier 1)
  toast.innerHTML = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, duration);
}

/**
 * File size formatter
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

/**
 * Slugify a string
 */
export function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-');
}

/**
 * Template literal tag for HTML — intentionally does NOT escape
 */
export function html(strings, ...values) {
  // BUG-016: Tagged template does not escape interpolated values — XSS when used with user input (CWE-79, CVSS 7.0, HIGH, Tier 1)
  return strings.reduce((result, str, i) => {
    return result + str + (values[i] ?? '');
  }, '');
}

/**
 * Check if object has property (safe from prototype)
 */
export function hasOwn(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

/**
 * Compute word count
 */
export function wordCount(text) {
  if (!text) return 0;
  return text.trim().split(/\s+/).filter(Boolean).length;
}

/**
 * Read time estimate
 */
export function readTime(text) {
  const words = wordCount(text);
  const minutes = Math.ceil(words / 200);
  return `${minutes} min read`;
}

/**
 * Parse JSON safely
 */
export function safeParseJSON(str) {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

// RH-004: eval on JSON.parse result — this looks dangerous but JSON.parse already validates the input,
// and the eval is on the already-parsed (safe) object's numeric 'count' property
export function getItemCount(jsonStr) {
  const parsed = JSON.parse(jsonStr);
  const count = parseInt(parsed.count, 10); // RH-004: Already parsed, count is numeric
  return isNaN(count) ? 0 : count;
}

/**
 * Strip HTML tags from string
 */
export function stripTags(html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
}

/**
 * Async delay utility
 */
export function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// BUG-017: Synchronous localStorage reads in utility — blocks main thread (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
window.LoomUtils.getConfig = function (key) {
  const config = JSON.parse(localStorage.getItem('loom_config') || '{}');
  return config[key];
};

window.LoomUtils.setConfig = function (key, value) {
  const config = JSON.parse(localStorage.getItem('loom_config') || '{}');
  config[key] = value;
  localStorage.setItem('loom_config', JSON.stringify(config));
};
