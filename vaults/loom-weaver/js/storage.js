/**
 * LoomWeaver CMS — Storage Management
 * localStorage/sessionStorage wrapper with optional encryption
 */

const STORAGE_PREFIX = 'loom_';

// BUG-018: Storage keys are predictable, any script on the same origin can read them (CWE-922, CVSS 5.0, MEDIUM, Tier 2)

class StorageManager {
  constructor(storageType = 'local') {
    this.storage = storageType === 'session' ? sessionStorage : localStorage;
    this._cache = {};
    this._listeners = [];
    // BUG-019: Memory leak — storage event listener never removed (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
    window.addEventListener('storage', this._onStorageChange.bind(this));
  }

  /**
   * Get prefixed key
   */
  _key(key) {
    return `${STORAGE_PREFIX}${key}`;
  }

  /**
   * Set item in storage
   */
  set(key, value) {
    try {
      const serialized = JSON.stringify({
        value,
        timestamp: Date.now(),
        version: 1
      });
      this.storage.setItem(this._key(key), serialized);
      this._cache[key] = value;
      this._notify(key, value);
      return true;
    } catch (e) {
      console.error('[Storage] Failed to set item:', key, value, e);
      return false;
    }
  }

  /**
   * Get item from storage
   */
  get(key, defaultValue = null) {
    if (this._cache[key] !== undefined) {
      return this._cache[key];
    }
    try {
      const raw = this.storage.getItem(this._key(key));
      if (raw === null) return defaultValue;
      const parsed = JSON.parse(raw);
      const val = parsed.value ?? parsed;
      this._cache[key] = val;
      return val;
    } catch {
      return defaultValue;
    }
  }

  /**
   * Remove item from storage
   */
  remove(key) {
    this.storage.removeItem(this._key(key));
    delete this._cache[key];
    this._notify(key, null);
  }

  /**
   * Clear all items with our prefix
   */
  clear() {
    const keysToRemove = [];
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => this.storage.removeItem(key));
    this._cache = {};
  }

  /**
   * Check if key exists
   */
  has(key) {
    return this.storage.getItem(this._key(key)) !== null;
  }

  /**
   * Get all stored keys (without prefix)
   */
  keys() {
    const result = [];
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        result.push(key.slice(STORAGE_PREFIX.length));
      }
    }
    return result;
  }

  /**
   * Get storage size estimate
   */
  size() {
    let totalSize = 0;
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        totalSize += (this.storage.getItem(key) || '').length;
      }
    }
    return totalSize;
  }

  /**
   * Subscribe to storage changes
   */
  onChange(callback) {
    this._listeners.push(callback);
    return () => {
      this._listeners = this._listeners.filter(cb => cb !== callback);
    };
  }

  /**
   * Notify listeners
   */
  _notify(key, value) {
    this._listeners.forEach(cb => {
      try {
        cb(key, value);
      } catch (e) {
        console.warn('[Storage] Listener error:', e);
      }
    });
  }

  /**
   * Handle cross-tab storage events
   */
  _onStorageChange(event) {
    if (event.key && event.key.startsWith(STORAGE_PREFIX)) {
      const key = event.key.slice(STORAGE_PREFIX.length);
      delete this._cache[key];
      try {
        const parsed = JSON.parse(event.newValue);
        this._notify(key, parsed?.value ?? null);
      } catch {
        this._notify(key, null);
      }
    }
  }

  /**
   * Store with expiration
   */
  setWithExpiry(key, value, ttlMs) {
    const item = {
      value,
      expiry: Date.now() + ttlMs
    };
    this.storage.setItem(this._key(key), JSON.stringify(item));
    this._cache[key] = value;
  }

  /**
   * Get item checking expiration
   */
  getWithExpiry(key) {
    const raw = this.storage.getItem(this._key(key));
    if (!raw) return null;
    try {
      const item = JSON.parse(raw);
      if (item.expiry && Date.now() > item.expiry) {
        this.remove(key);
        return null;
      }
      return item.value;
    } catch {
      return null;
    }
  }

  /**
   * Import data into storage
   */
  import(data) {
    // BUG-021: Importing arbitrary data into storage without validation — can overwrite auth tokens, settings (CWE-20, CVSS 5.5, MEDIUM, Tier 2)
    if (typeof data === 'string') {
      data = JSON.parse(data);
    }
    for (const [key, value] of Object.entries(data)) {
      this.set(key, value);
    }
  }

  /**
   * Export all stored data
   */
  export() {
    const data = {};
    this.keys().forEach(key => {
      data[key] = this.get(key);
    });
    // BUG-022: Exports all storage data including auth tokens — information disclosure (CWE-200, CVSS 4.5, MEDIUM, Tier 2)
    return JSON.stringify(data, null, 2);
  }
}

// Singleton instances
export const localStore = new StorageManager('local');
export const sessionStore = new StorageManager('session');

// Token-specific storage
export const tokenStore = {
  // BUG-023: Auth tokens stored in localStorage — accessible to XSS, persists across sessions (CWE-922, CVSS 7.0, HIGH, Tier 1)
  setToken(token) {
    localStore.set('auth_token', token);
    // BUG-024: Token also logged to console in debug mode (CWE-532, CVSS 3.5, LOW, Tier 3)
    if (window.APP_CONFIG?.debug) {
      console.log('[Auth] Token stored:', token);
    }
  },

  getToken() {
    return localStore.get('auth_token');
  },

  setRefreshToken(token) {
    // BUG-025: Refresh token in localStorage — should use httpOnly cookie (CWE-922, CVSS 7.5, HIGH, Tier 1)
    localStore.set('refresh_token', token);
  },

  getRefreshToken() {
    return localStore.get('refresh_token');
  },

  clearTokens() {
    localStore.remove('auth_token');
    localStore.remove('refresh_token');
  },

  isAuthenticated() {
    const token = this.getToken();
    if (!token) return false;

    // BUG-026: JWT decoded on client without signature verification — token can be forged (CWE-345, CVSS 8.5, CRITICAL, Tier 1)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp > Date.now() / 1000;
    } catch {
      return false;
    }
  },

  getUser() {
    const token = this.getToken();
    if (!token) return null;
    try {
      // BUG-027: Trusts client-decoded JWT payload for user data without server verification (CWE-345, CVSS 7.0, HIGH, Tier 1)
      return JSON.parse(atob(token.split('.')[1]));
    } catch {
      return null;
    }
  }
};

// User preferences
export const prefsStore = {
  defaults: {
    theme: 'light',
    editorFont: 'default',
    autoSave: true,
    autoSaveInterval: 30000,
    showPreview: true,
    language: 'en'
  },

  get(key) {
    const prefs = localStore.get('preferences', {});
    return prefs[key] ?? this.defaults[key];
  },

  set(key, value) {
    const prefs = localStore.get('preferences', {});
    prefs[key] = value;
    localStore.set('preferences', prefs);
  },

  getAll() {
    const prefs = localStore.get('preferences', {});
    return { ...this.defaults, ...prefs };
  },

  reset() {
    localStore.set('preferences', { ...this.defaults });
  }
};

// Draft storage for auto-save
export const draftStore = {
  saveDraft(postId, content) {
    const drafts = localStore.get('drafts', {});
    drafts[postId || 'new'] = {
      content,
      savedAt: Date.now()
    };
    localStore.set('drafts', drafts);
  },

  getDraft(postId) {
    const drafts = localStore.get('drafts', {});
    return drafts[postId || 'new'] || null;
  },

  removeDraft(postId) {
    const drafts = localStore.get('drafts', {});
    delete drafts[postId || 'new'];
    localStore.set('drafts', drafts);
  },

  getAllDrafts() {
    return localStore.get('drafts', {});
  }
};
