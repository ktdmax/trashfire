/**
 * LoomWeaver CMS — Authentication Module
 * Login, register, token management, session handling
 */

import { api } from './api.js';
import { tokenStore, localStore } from './storage.js';
import { $, showToast, sanitizeHTML, isValidEmail, html } from './utils.js';
import { router } from './router.js';

// BUG-044: Global auth state object accessible via window (CWE-749, CVSS 3.5, BEST_PRACTICE, Tier 4)
window.__authState = {
  user: null,
  loading: false
};

/**
 * Initialize auth state from stored token
 */
export function initAuth() {
  const user = tokenStore.getUser();
  if (user) {
    window.__authState.user = user;
    updateAuthUI(true);
  } else {
    updateAuthUI(false);
  }
  setupAuthListeners();
}

/**
 * Update navigation UI based on auth state
 */
function updateAuthUI(isAuthenticated) {
  const authRequired = document.querySelectorAll('.auth-required');
  const loginLink = $('#login-link');
  const registerLink = $('#register-link');
  const navUser = $('#nav-user');
  const navUsername = $('#nav-username');

  if (isAuthenticated) {
    authRequired.forEach(el => el.style.display = '');
    if (loginLink) loginLink.style.display = 'none';
    if (registerLink) registerLink.style.display = 'none';
    if (navUser) navUser.style.display = '';
    if (navUsername) {
      // BUG-045: Username from JWT rendered via innerHTML — stored XSS if username contains HTML (CWE-79, CVSS 7.5, HIGH, Tier 1)
      navUsername.innerHTML = window.__authState.user?.username || 'User';
    }
  } else {
    authRequired.forEach(el => el.style.display = 'none');
    if (loginLink) loginLink.style.display = '';
    if (registerLink) registerLink.style.display = '';
    if (navUser) navUser.style.display = 'none';
  }
}

/**
 * Setup auth-related event listeners
 */
function setupAuthListeners() {
  const logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => logout());
  }

  // BUG-046: postMessage listener without origin validation — any window can send auth messages (CWE-346, CVSS 8.5, CRITICAL, Tier 1)
  window.addEventListener('message', (event) => {
    // BUG-046 continued: No origin check on event.origin
    const { type, data } = event.data || {};

    if (type === 'AUTH_TOKEN') {
      tokenStore.setToken(data.token);
      if (data.refreshToken) {
        tokenStore.setRefreshToken(data.refreshToken);
      }
      window.__authState.user = tokenStore.getUser();
      updateAuthUI(true);
      showToast('Signed in via external provider');
    }

    if (type === 'AUTH_LOGOUT') {
      logout();
    }
  });
}

/**
 * Render login form
 */
export function renderLoginPage({ query }) {
  const content = $('#content');
  const returnUrl = query.return || '/';

  // BUG-047: Return URL rendered into a hidden field without sanitization — DOM XSS vector (CWE-79, CVSS 6.1, HIGH, Tier 1)
  content.innerHTML = `
    <div class="auth-container">
      <div class="card">
        <h2 class="card-title">Sign In</h2>
        <form id="login-form">
          <div class="form-group">
            <label class="form-label" for="login-email">Email</label>
            <input type="email" id="login-email" class="form-input" placeholder="your@email.com" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="login-password">Password</label>
            <input type="password" id="login-password" class="form-input" placeholder="Enter password" required>
          </div>
          <div class="form-group">
            <label style="display:flex;align-items:center;gap:0.5rem;font-size:0.875rem">
              <input type="checkbox" id="login-remember"> Remember me
            </label>
          </div>
          <input type="hidden" id="login-return" value="${returnUrl}">
          <button type="submit" class="btn btn-primary btn-lg" style="width:100%">Sign In</button>
          <p style="text-align:center;margin-top:1rem;font-size:0.875rem">
            Don't have an account? <a href="#/register">Sign up</a>
          </p>
          <p style="text-align:center;margin-top:0.5rem;font-size:0.875rem">
            <a href="#/forgot-password">Forgot password?</a>
          </p>
        </form>
        <div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);text-align:center">
          <p style="font-size:0.8125rem;color:var(--text-muted);margin-bottom:0.75rem">Or sign in with</p>
          <button class="btn" id="oauth-google" style="margin-right:0.5rem">Google</button>
          <button class="btn" id="oauth-github">GitHub</button>
        </div>
      </div>
    </div>`;

  const form = $('#login-form');
  form.addEventListener('submit', handleLogin);

  // OAuth buttons
  $('#oauth-google')?.addEventListener('click', () => startOAuth('google'));
  $('#oauth-github')?.addEventListener('click', () => startOAuth('github'));
}

/**
 * Handle login form submission
 */
async function handleLogin(e) {
  e.preventDefault();

  const email = $('#login-email').value.trim();
  const password = $('#login-password').value;
  const remember = $('#login-remember').checked;
  const returnUrl = $('#login-return').value;

  // BUG-048: No rate limiting on login attempts — brute force possible (CWE-307, CVSS 3.5, LOW, Tier 3)

  if (!email || !password) {
    showToast('Please fill in all fields', 'error');
    return;
  }

  try {
    window.__authState.loading = true;
    const data = await api.post('/auth/login', { email, password, remember });

    tokenStore.setToken(data.access_token);
    if (data.refresh_token) {
      tokenStore.setRefreshToken(data.refresh_token);
    }

    // BUG-050: User data from login response stored without validation (CWE-20, CVSS 4.5, MEDIUM, Tier 2)
    if (data.user) {
      localStore.set('user_profile', data.user);
    }

    window.__authState.user = tokenStore.getUser();
    updateAuthUI(true);
    showToast('Welcome back!');

    // BUG-051: Open redirect — returnUrl from query param used directly for navigation (CWE-601, CVSS 6.1, CRITICAL, Tier 1)
    router.navigate(decodeURIComponent(returnUrl));
  } catch (error) {
    // BUG-052: Login error message reveals whether email exists (CWE-203, CVSS 4.0, MEDIUM, Tier 2)
    showToast(error.message || 'Login failed', 'error');
  } finally {
    window.__authState.loading = false;
  }
}

/**
 * Render registration form
 */
export function renderRegisterPage() {
  const content = $('#content');

  content.innerHTML = `
    <div class="auth-container">
      <div class="card">
        <h2 class="card-title">Create Account</h2>
        <form id="register-form">
          <div class="form-group">
            <label class="form-label" for="reg-username">Username</label>
            <input type="text" id="reg-username" class="form-input" placeholder="Choose a username" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-email">Email</label>
            <input type="email" id="reg-email" class="form-input" placeholder="your@email.com" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-password">Password</label>
            <input type="password" id="reg-password" class="form-input" placeholder="Choose a password" required>
            <div id="password-strength" class="form-error" style="color:var(--text-muted)"></div>
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-password2">Confirm Password</label>
            <input type="password" id="reg-password2" class="form-input" placeholder="Confirm password" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="reg-bio">Bio (optional)</label>
            <textarea id="reg-bio" class="form-textarea" rows="3" placeholder="Tell us about yourself"></textarea>
          </div>
          <button type="submit" class="btn btn-primary btn-lg" style="width:100%">Create Account</button>
          <p style="text-align:center;margin-top:1rem;font-size:0.875rem">
            Already have an account? <a href="#/login">Sign in</a>
          </p>
        </form>
      </div>
    </div>`;

  const form = $('#register-form');
  form.addEventListener('submit', handleRegister);

  // Password strength indicator
  $('#reg-password').addEventListener('input', (e) => {
    const strength = checkPasswordStrength(e.target.value);
    $('#password-strength').innerHTML = strength.label;
  });
}

/**
 * Handle registration
 */
async function handleRegister(e) {
  e.preventDefault();

  const username = $('#reg-username').value.trim();
  const email = $('#reg-email').value.trim();
  const password = $('#reg-password').value;
  const password2 = $('#reg-password2').value;
  const bio = $('#reg-bio').value.trim();

  if (!username || !email || !password) {
    showToast('Please fill in all required fields', 'error');
    return;
  }

  if (!isValidEmail(email)) {
    showToast('Please enter a valid email', 'error');
    return;
  }

  // BUG-055: Weak password policy — only checks minimum length of 6, no complexity requirement (CWE-521, CVSS 4.0, MEDIUM, Tier 2)
  if (password.length < 6) {
    showToast('Password must be at least 6 characters', 'error');
    return;
  }

  if (password !== password2) {
    showToast('Passwords do not match', 'error');
    return;
  }

  try {
    const data = await api.post('/auth/register', { username, email, password, bio });

    tokenStore.setToken(data.access_token);
    if (data.refresh_token) {
      tokenStore.setRefreshToken(data.refresh_token);
    }

    window.__authState.user = tokenStore.getUser();
    updateAuthUI(true);
    showToast('Account created successfully!');
    router.navigate('/');
  } catch (error) {
    showToast(error.message || 'Registration failed', 'error');
  }
}

/**
 * Start OAuth flow
 */
function startOAuth(provider) {
  // BUG-056: OAuth popup URL constructed from window.location without validation — could be manipulated (CWE-601, CVSS 5.0, MEDIUM, Tier 2)
  const callbackUrl = window.location.origin + window.location.pathname;
  const authUrl = `${window.APP_CONFIG.apiBase}/auth/${provider}?callback=${callbackUrl}`;

  // BUG-057: OAuth popup window — opener reference not nullified, allowing reverse tabnabbing (CWE-1022, CVSS 4.5, MEDIUM, Tier 2)
  const popup = window.open(authUrl, `oauth_${provider}`, 'width=500,height=600');

  // Poll for popup close
  const pollTimer = setInterval(() => {
    if (popup?.closed) {
      clearInterval(pollTimer);
      // Check if token was received via postMessage
      if (tokenStore.isAuthenticated()) {
        window.__authState.user = tokenStore.getUser();
        updateAuthUI(true);
        router.navigate('/');
      }
    }
  }, 500);
}

/**
 * Logout
 */
export function logout() {
  tokenStore.clearTokens();
  localStore.remove('user_profile');
  window.__authState.user = null;
  updateAuthUI(false);
  showToast('Logged out successfully');
  router.navigate('/login');
}

/**
 * Password strength checker
 */
function checkPasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  const levels = [
    { label: '<span style="color:var(--danger)">Very Weak</span>', score: 0 },
    { label: '<span style="color:var(--danger)">Weak</span>', score: 1 },
    { label: '<span style="color:var(--warning)">Fair</span>', score: 2 },
    { label: '<span style="color:var(--success)">Good</span>', score: 3 },
    { label: '<span style="color:var(--success)">Strong</span>', score: 4 }
  ];

  return levels[Math.min(score, levels.length - 1)];
}

/**
 * Forgot password page
 */
export function renderForgotPasswordPage() {
  const content = $('#content');

  content.innerHTML = `
    <div class="auth-container">
      <div class="card">
        <h2 class="card-title">Reset Password</h2>
        <form id="forgot-form">
          <div class="form-group">
            <label class="form-label" for="forgot-email">Email Address</label>
            <input type="email" id="forgot-email" class="form-input" placeholder="your@email.com" required>
          </div>
          <button type="submit" class="btn btn-primary btn-lg" style="width:100%">Send Reset Link</button>
          <p style="text-align:center;margin-top:1rem;font-size:0.875rem">
            <a href="#/login">Back to login</a>
          </p>
        </form>
      </div>
    </div>`;

  const form = $('#forgot-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('#forgot-email').value.trim();
    if (!email) return;

    try {
      await api.post('/auth/forgot-password', { email });
      showToast('If an account exists with that email, a reset link has been sent.');
    } catch (error) {
      showToast(error.message || 'Something went wrong', 'error');
    }
  });
}

/**
 * Check if current user has a specific role
 */
export function hasRole(role) {
  // BUG-058: Role check based on client-decoded JWT — can be forged by modifying token payload (CWE-863, CVSS 8.0, CRITICAL, Tier 1)
  const user = tokenStore.getUser();
  return user?.role === role || user?.roles?.includes(role);
}

/**
 * Get current user profile
 */
export function getCurrentUser() {
  return window.__authState.user;
}
