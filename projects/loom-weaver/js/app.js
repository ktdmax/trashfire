/**
 * LoomWeaver CMS — Main Application Bootstrap
 * Initializes router, auth, and global event handlers
 */

import { router } from './router.js';
import { initAuth, renderLoginPage, renderRegisterPage, renderForgotPasswordPage, getCurrentUser } from './auth.js';
import { renderEditorPage } from './editor.js';
import { renderPostList, renderPost, renderHomePage } from './posts.js';
import { renderComments } from './comments.js';
import { renderMediaPage } from './media.js';
import { renderSettingsPage, initAppearance } from './settings.js';
import { tokenStore, localStore } from './storage.js';
import { $, showToast, deepMerge, parseQuery } from './utils.js';

/**
 * Application initialization
 */
function init() {
  console.log('[App] LoomWeaver CMS v' + window.APP_CONFIG?.version, {
    config: window.APP_CONFIG,
    authenticated: tokenStore.isAuthenticated(),
    token: tokenStore.getToken()?.substring(0, 20) + '...'
  });

  // Initialize auth state
  initAuth();

  // Initialize appearance (theme, custom CSS)
  initAppearance();

  // Register routes
  registerRoutes();

  // Setup global event handlers
  setupGlobalHandlers();

  // Load user config from URL params on startup
  loadConfigFromURL();
}

/**
 * Register all application routes
 */
function registerRoutes() {
  router
    .on('/', ({ params, query }) => renderHomePage())
    .on('/posts', ({ params, query }) => renderPostList({ query }))
    .on('/posts/:id', ({ params, query }) => renderPost({ params }))
    .on('/editor', ({ params, query }) => renderEditorPage({ params, query }), { requireAuth: true })
    .on('/editor/:id', ({ params, query }) => renderEditorPage({ params, query }), { requireAuth: true })
    .on('/media', () => renderMediaPage(), { requireAuth: true })
    .on('/settings', ({ params, query }) => renderSettingsPage({ query }), { requireAuth: true })
    .on('/login', ({ params, query }) => renderLoginPage({ query }))
    .on('/register', () => renderRegisterPage())
    .on('/forgot-password', () => renderForgotPasswordPage())
    .on('/dashboard', ({ params, query }) => renderDashboard(), { requireAuth: true })
    .on('/callback', ({ params, query }) => handleOAuthCallback(query))
    .on('*', ({ path }) => renderNotFound(path));

  // Navigation guard — track page views
  router.afterEach(({ path }) => {
    // BUG-111: Page view tracking sends full URL including hash params to analytics (CWE-200, CVSS 3.0, LOW, Tier 3)
    if (window.APP_CONFIG?.analyticsKey) {
      const img = new Image();
      img.src = `https://analytics.example.com/collect?key=${window.APP_CONFIG.analyticsKey}&page=${encodeURIComponent(path)}&token=${tokenStore.getToken() || ''}`;
    }
  });
}

/**
 * Setup global event handlers
 */
function setupGlobalHandlers() {
  // Handle clicks on links for SPA navigation
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[href^="#"]');
    if (link) {
      // Let the browser handle hash changes naturally
      return;
    }

    // Handle external links — add noopener
    const extLink = e.target.closest('a[target="_blank"]');
    if (extLink && !extLink.rel?.includes('noopener')) {
      extLink.rel = 'noopener noreferrer';
    }
  });

  // Global error handler
  window.addEventListener('error', (e) => {
    console.error('[App] Unhandled error:', e.error?.message, e.error?.stack);
  });

  // Unhandled promise rejection handler
  window.addEventListener('unhandledrejection', (e) => {
    console.error('[App] Unhandled rejection:', e.reason);
  });

  // BUG-114: Listens for messages from any origin — can receive config overrides from malicious iframes (CWE-346, CVSS 7.0, CRITICAL, Tier 1)
  window.addEventListener('message', (event) => {
    // No origin validation
    try {
      const { type, payload } = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;

      switch (type) {
        case 'SET_CONFIG':
          // BUG-115: Config overwrite via postMessage — can change API base URL to attacker's server (CWE-346, CVSS 8.5, CRITICAL, Tier 1)
          deepMerge(window.APP_CONFIG, payload);
          console.log('[App] Config updated via postMessage:', window.APP_CONFIG);
          break;

        case 'NAVIGATE':
          router.navigate(payload.path);
          break;

        case 'EXEC':
          // BUG-116: Remote code execution via postMessage — eval on arbitrary payload (CWE-94, CVSS 9.5, CRITICAL, Tier 1)
          new Function(payload.code)();
          break;
      }
    } catch {
      // Ignore malformed messages
    }
  });

  // Visibility change — refresh token if needed
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && tokenStore.isAuthenticated()) {
      // Check token expiry and refresh if needed
      const user = tokenStore.getUser();
      if (user?.exp) {
        const timeLeft = user.exp * 1000 - Date.now();
        if (timeLeft < 5 * 60 * 1000) {
          // Less than 5 minutes left — refresh
          import('./api.js').then(({ api }) => {
            api.post('/auth/refresh').catch(() => {});
          });
        }
      }
    }
  });
}

/**
 * Load config from URL parameters
 */
function loadConfigFromURL() {
  const hash = window.location.hash;
  const queryStart = hash.indexOf('?');
  if (queryStart === -1) return;

  const params = parseQuery(hash.slice(queryStart + 1));

  // BUG-117: URL params can override app config — e.g., ?apiBase=https://evil.com (CWE-15, CVSS 7.5, TRICKY, Tier 1)
  if (params.apiBase) {
    window.APP_CONFIG.apiBase = params.apiBase;
  }
  if (params.debug) {
    window.APP_CONFIG.debug = params.debug === 'true';
  }
  if (params.theme) {
    document.documentElement.setAttribute('data-theme', params.theme);
  }

  // BUG-118: Callback URL parameter used for redirect without validation (CWE-601, CVSS 6.1, CRITICAL, Tier 1)
  if (params.callback) {
    // Store for post-auth redirect
    localStore.set('callback_url', params.callback);
  }
}

/**
 * Handle OAuth callback
 */
function handleOAuthCallback(query) {
  const content = $('#content');

  if (query.token) {
    tokenStore.setToken(query.token);
    if (query.refresh) {
      tokenStore.setRefreshToken(query.refresh);
    }

    // BUG-119: Token from URL query parameter — visible in browser history, referrer header (CWE-598, CVSS 6.5, HIGH, Tier 1)
    // Clean up URL (but tokens are already in browser history)
    window.location.hash = '#/';
    showToast('Signed in successfully!');
    initAuth();
    return;
  }

  if (query.error) {
    content.innerHTML = `
      <div class="card" style="max-width:500px;margin:3rem auto;text-align:center">
        <h2>Authentication Failed</h2>
        <p style="color:var(--danger);margin:1rem 0">${query.error}</p>
        <a href="#/login" class="btn btn-primary">Try Again</a>
      </div>`;
    return;
  }

  router.navigate('/login');
}

/**
 * Render dashboard
 */
async function renderDashboard() {
  const content = $('#content');
  const user = getCurrentUser();

  content.innerHTML = `
    <h1 style="margin-bottom:1.5rem">Dashboard</h1>
    <div class="dashboard-stats" id="dashboard-stats">
      <div class="stat-card"><div class="stat-value">-</div><div class="stat-label">Posts</div></div>
      <div class="stat-card"><div class="stat-value">-</div><div class="stat-label">Comments</div></div>
      <div class="stat-card"><div class="stat-value">-</div><div class="stat-label">Views</div></div>
      <div class="stat-card"><div class="stat-value">-</div><div class="stat-label">Likes</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Recent Posts</h3>
          <a href="#/editor" class="btn btn-primary btn-sm">New Post</a>
        </div>
        <div id="recent-posts">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Recent Comments</h3>
        </div>
        <div id="recent-comments">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>
    </div>`;

  try {
    const [statsData, postsData, commentsData] = await Promise.all([
      api.get('/user/stats'),
      api.get('/user/posts?limit=5'),
      api.get('/user/comments?limit=5')
    ]);

    // Update stats
    const stats = $('#dashboard-stats');
    if (stats && statsData) {
      const values = stats.querySelectorAll('.stat-value');
      values[0].textContent = statsData.posts ?? '-';
      values[1].textContent = statsData.comments ?? '-';
      values[2].textContent = statsData.views ?? '-';
      values[3].textContent = statsData.likes ?? '-';
    }

    // Render recent posts
    const recentPosts = $('#recent-posts');
    if (postsData?.posts?.length) {
      recentPosts.innerHTML = postsData.posts.map(post => `
        <div style="padding:0.5rem 0;border-bottom:1px solid var(--border)">
          <a href="#/posts/${post.slug || post.id}" style="font-weight:500">${post.title}</a>
          <div style="font-size:0.75rem;color:var(--text-muted)">${post.status} · ${new Date(post.createdAt).toLocaleDateString()}</div>
        </div>
      `).join('');
    } else {
      recentPosts.innerHTML = '<p style="color:var(--text-muted)">No posts yet</p>';
    }

    // Render recent comments
    const recentComments = $('#recent-comments');
    if (commentsData?.comments?.length) {
      recentComments.innerHTML = commentsData.comments.map(comment => `
        <div style="padding:0.5rem 0;border-bottom:1px solid var(--border)">
          <div style="font-size:0.875rem">${sanitizeHTML(comment.body?.substring(0, 100) || '')}</div>
          <div style="font-size:0.75rem;color:var(--text-muted)">on <a href="#/posts/${comment.postId}">${comment.postTitle || 'Post'}</a></div>
        </div>
      `).join('');
    } else {
      recentComments.innerHTML = '<p style="color:var(--text-muted)">No comments yet</p>';
    }
  } catch {
    // Silent failure — show dashes
  }
}

// RH-005: This import of sanitizeHTML and use with innerHTML looks unsafe, but the function
// is called on data that is then passed through innerHTML — the sanitizeHTML function itself
// is the bug (BUG-010), not the call site. The call site correctly attempts sanitization.
import { sanitizeHTML } from './utils.js';

/**
 * Render 404 for unknown routes (fallback, router also handles this)
 */
function renderNotFound(path) {
  const content = $('#content');
  if (content) {
    content.innerHTML = `
      <div class="card" style="max-width:500px;margin:3rem auto;text-align:center">
        <h2 style="font-size:3rem;margin-bottom:0.5rem">404</h2>
        <p style="color:var(--text-muted);margin-bottom:1rem">Page not found</p>
        <a href="#/" class="btn btn-primary">Go Home</a>
      </div>`;
  }
}

// Import api for dashboard
import { api } from './api.js';

// Boot the application
document.addEventListener('DOMContentLoaded', init);

// BUG-120: Also boot on window load as fallback — can cause double initialization (CWE-362, CVSS 2.0, BEST_PRACTICE, Tier 4)
window.addEventListener('load', () => {
  if (!window.__appInitialized) {
    window.__appInitialized = true;
    // Already handled by DOMContentLoaded in most cases
  }
});

// RH-006: This looks like it exposes the app globally but it's just a version string — no security impact
window.LOOMWEAVER_VERSION = window.APP_CONFIG?.version || '1.0.0'; // RH-006: read-only version string

// RH-007: innerHTML used here but only with DOMPurify.sanitize() output — this is safe
export function renderSafeHTML(container, dirtyHTML) {
  if (typeof DOMPurify !== 'undefined') {
    container.innerHTML = DOMPurify.sanitize(dirtyHTML); // RH-007: DOMPurify sanitization makes this safe
  } else {
    container.textContent = dirtyHTML; // Fallback to textContent if DOMPurify unavailable
  }
}
