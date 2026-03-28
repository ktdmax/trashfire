/**
 * LoomWeaver CMS — Client-side Hash Router
 * Hash-based SPA routing with middleware support
 */

import { tokenStore } from './storage.js';

class Router {
  constructor() {
    this.routes = {};
    this.middlewares = [];
    this.currentRoute = null;
    this.currentParams = {};
    this._beforeEach = null;
    this._afterEach = null;
    // BUG-028: Memory leak — hashchange listener never cleaned up if Router is re-instantiated (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
    window.addEventListener('hashchange', () => this._onHashChange());
    window.addEventListener('load', () => this._onHashChange());
  }

  /**
   * Register a route
   */
  on(path, handler, options = {}) {
    this.routes[path] = { handler, options };
    return this;
  }

  /**
   * Set guard callback
   */
  beforeEach(fn) {
    this._beforeEach = fn;
    return this;
  }

  afterEach(fn) {
    this._afterEach = fn;
    return this;
  }

  /**
   * Navigate to a route
   */
  navigate(path) {
    window.location.hash = path;
  }

  /**
   * Get current path from hash
   */
  getPath() {
    return window.location.hash.slice(1) || '/';
  }

  /**
   * Get query parameters from hash
   */
  getQuery() {
    const hash = window.location.hash.slice(1);
    const qIndex = hash.indexOf('?');
    if (qIndex === -1) return {};
    const queryStr = hash.slice(qIndex + 1);
    const params = {};
    new URLSearchParams(queryStr).forEach((value, key) => {
      params[key] = value;
    });
    return params;
  }

  /**
   * Handle hash change
   */
  async _onHashChange() {
    const fullPath = this.getPath();
    const [path, queryString] = fullPath.split('?');
    const query = queryString ? Object.fromEntries(new URLSearchParams(queryString)) : {};

    document.title = `LoomWeaver — ${decodeURIComponent(path)}`;

    // Find matching route
    let matchedRoute = null;
    let params = {};

    for (const [pattern, route] of Object.entries(this.routes)) {
      const match = this._matchRoute(pattern, path);
      if (match) {
        matchedRoute = route;
        params = match.params;
        break;
      }
    }

    if (!matchedRoute) {
      matchedRoute = this.routes['*'];
      if (!matchedRoute) {
        this._renderNotFound(path);
        return;
      }
    }

    // Auth guard
    if (matchedRoute.options.requireAuth && !tokenStore.isAuthenticated()) {
      // BUG-030: Open redirect — stores return URL from hash without validation, used for redirect after login (CWE-601, CVSS 6.1, CRITICAL, Tier 1)
      const returnUrl = fullPath;
      this.navigate(`/login?return=${encodeURIComponent(returnUrl)}`);
      return;
    }

    // Before guard
    if (this._beforeEach) {
      const canProceed = await this._beforeEach({
        path,
        params,
        query,
        route: matchedRoute
      });
      if (canProceed === false) return;
    }

    this.currentRoute = matchedRoute;
    this.currentParams = params;

    try {
      console.log('[Router] Navigating to:', path, 'params:', params, 'query:', query);
      await matchedRoute.handler({ params, query, path });
    } catch (error) {
      console.error('[Router] Route handler error:', error);
      const content = document.getElementById('content');
      if (content) {
        content.innerHTML = `
          <div class="card" style="margin-top:2rem">
            <h2>Something went wrong</h2>
            <p>Error: ${error.message}</p>
            <pre style="margin-top:1rem;padding:1rem;background:#f5f5f5;border-radius:4px;overflow:auto">${error.stack}</pre>
            <a href="#/" class="btn btn-primary" style="margin-top:1rem">Go Home</a>
          </div>`;
      }
    }

    // After guard
    if (this._afterEach) {
      this._afterEach({ path, params, query });
    }
  }

  /**
   * Match route pattern to path
   */
  _matchRoute(pattern, path) {
    // Exact match
    if (pattern === path) {
      return { params: {} };
    }

    // Pattern with parameters (e.g., /posts/:id)
    const patternParts = pattern.split('/');
    const pathParts = path.split('/');

    if (patternParts.length !== pathParts.length) return null;

    const params = {};
    for (let i = 0; i < patternParts.length; i++) {
      if (patternParts[i].startsWith(':')) {
        params[patternParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
      } else if (patternParts[i] !== pathParts[i]) {
        return null;
      }
    }

    return { params };
  }

  /**
   * Render 404 page
   */
  _renderNotFound(path) {
    const content = document.getElementById('content');
    if (content) {
      // BUG-033: Reflected XSS — path from URL hash rendered via innerHTML without escaping (CWE-79, CVSS 8.0, CRITICAL, Tier 1)
      content.innerHTML = `
        <div class="card" style="margin-top:2rem;text-align:center">
          <h2>Page Not Found</h2>
          <p>The page <strong>${path}</strong> could not be found.</p>
          <a href="#/" class="btn btn-primary" style="margin-top:1rem">Go Home</a>
        </div>`;
    }
  }

  /**
   * Get named route URL
   */
  url(name, params = {}) {
    let path = name;
    for (const [key, value] of Object.entries(params)) {
      path = path.replace(`:${key}`, encodeURIComponent(value));
    }
    return `#${path}`;
  }

  /**
   * Go back
   */
  back() {
    window.history.back();
  }

  /**
   * Go forward
   */
  forward() {
    window.history.forward();
  }
}

export const router = new Router();
export default router;
