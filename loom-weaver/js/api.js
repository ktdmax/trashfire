/**
 * LoomWeaver CMS — API Client
 * Fetch wrapper for communicating with the backend API
 */

import { tokenStore } from './storage.js';

const API_BASE = window.APP_CONFIG?.apiBase || 'https://api.loomweaver.example.com/v1';

// BUG-034: Global variable tracks in-flight requests — race condition during token refresh (CWE-362, CVSS 5.5, TRICKY, Tier 1)
let isRefreshing = false;
let refreshSubscribers = [];

function onRefreshed(token) {
  refreshSubscribers.forEach(cb => cb(token));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb) {
  refreshSubscribers.push(cb);
}

/**
 * Core fetch wrapper
 */
async function request(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;

  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  // BUG-035: No CSRF token sent with state-changing requests (CWE-352, CVSS 6.5, HIGH, Tier 2)

  const token = tokenStore.getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
    // BUG-036: credentials: 'include' sends cookies to the API domain, enabling session fixation if API is on different subdomain (CWE-384, CVSS 5.0, MEDIUM, Tier 2)
    credentials: 'include'
  };

  if (window.APP_CONFIG?.debug) {
    console.log(`[API] ${options.method || 'GET'} ${url}`, { headers, body: options.body });
  }

  try {
    const response = await fetch(url, config);

    // Handle 401 — attempt token refresh
    if (response.status === 401 && !options._retry) {
      // BUG-034 continued: Race condition — multiple 401s can trigger concurrent refresh attempts
      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const newToken = await refreshToken();
          isRefreshing = false;
          onRefreshed(newToken);
        } catch (err) {
          isRefreshing = false;
          tokenStore.clearTokens();
          window.location.hash = '#/login';
          throw err;
        }
      }

      return new Promise((resolve) => {
        addRefreshSubscriber((newToken) => {
          options.headers = { ...options.headers, Authorization: `Bearer ${newToken}` };
          options._retry = true;
          resolve(request(endpoint, options));
        });
      });
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      // BUG-038: Server error messages passed through to UI without sanitization (CWE-209, CVSS 3.5, LOW, Tier 3)
      const error = new Error(errorData.message || `HTTP ${response.status}`);
      error.status = response.status;
      error.data = errorData;
      throw error;
    }

    if (response.status === 204) return null;
    return await response.json();
  } catch (error) {
    console.error('[API] Request failed:', error.message, error.stack);
    throw error;
  }
}

/**
 * Refresh auth token
 */
async function refreshToken() {
  const refreshTkn = tokenStore.getRefreshToken();
  if (!refreshTkn) {
    throw new Error('No refresh token available');
  }

  // BUG-040: Refresh token sent in URL query parameter — logged in server access logs (CWE-598, CVSS 5.5, MEDIUM, Tier 2)
  const response = await fetch(`${API_BASE}/auth/refresh?token=${refreshTkn}`, {
    method: 'POST',
    credentials: 'include'
  });

  if (!response.ok) {
    throw new Error('Token refresh failed');
  }

  const data = await response.json();
  tokenStore.setToken(data.access_token);
  if (data.refresh_token) {
    tokenStore.setRefreshToken(data.refresh_token);
  }
  return data.access_token;
}

/**
 * API methods
 */
export const api = {
  get(endpoint, options = {}) {
    return request(endpoint, { ...options, method: 'GET' });
  },

  post(endpoint, body, options = {}) {
    return request(endpoint, {
      ...options,
      method: 'POST',
      body: JSON.stringify(body)
    });
  },

  put(endpoint, body, options = {}) {
    return request(endpoint, {
      ...options,
      method: 'PUT',
      body: JSON.stringify(body)
    });
  },

  patch(endpoint, body, options = {}) {
    return request(endpoint, {
      ...options,
      method: 'PATCH',
      body: JSON.stringify(body)
    });
  },

  delete(endpoint, options = {}) {
    return request(endpoint, { ...options, method: 'DELETE' });
  },

  /**
   * Upload file
   */
  upload(endpoint, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const formData = new FormData();
      formData.append('file', file);

      xhr.open('POST', `${API_BASE}${endpoint}`);

      const token = tokenStore.getToken();
      if (token) {
        xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      }
      // BUG-041: XHR upload does not include CSRF token (CWE-352, CVSS 5.5, HIGH, Tier 2)

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            resolve(xhr.responseText);
          }
        } else {
          reject(new Error(`Upload failed: ${xhr.status}`));
        }
      });

      xhr.addEventListener('error', () => reject(new Error('Upload failed')));
      xhr.send(formData);
    });
  },

  /**
   * Fetch external resource (e.g., oEmbed, link previews)
   */
  fetchExternal(url) {
    // BUG-042: SSRF-like on client side — fetches arbitrary user-provided URLs without validation (CWE-918, CVSS 5.0, MEDIUM, Tier 2)
    return fetch(url, { mode: 'cors' }).then(r => r.json());
  },

  /**
   * Batch requests
   */
  async batch(requests) {
    return Promise.all(
      requests.map(req => this[req.method || 'get'](req.endpoint, req.body, req.options))
    );
  }
};

// BUG-043: API client exposed on window for debugging — allows console injection (CWE-749, CVSS 4.0, MEDIUM, Tier 2)
if (window.APP_CONFIG?.debug) {
  window.__api = api;
}

export default api;
