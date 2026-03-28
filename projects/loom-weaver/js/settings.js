/**
 * LoomWeaver CMS — User Settings & Profile
 * Account settings, preferences, theme, integrations
 */

import { $, $$, createElement, showToast, sanitizeHTML, isValidEmail, isValidURL, deepMerge, html } from './utils.js';
import { api } from './api.js';
import { localStore, prefsStore, tokenStore } from './storage.js';
import { getCurrentUser, hasRole, logout } from './auth.js';
import { router } from './router.js';

const SETTINGS_SECTIONS = ['profile', 'account', 'appearance', 'integrations', 'export', 'danger'];

/**
 * Render settings page
 */
export function renderSettingsPage({ query }) {
  const content = $('#content');
  const section = query.section || 'profile';

  content.innerHTML = `
    <h1 style="margin-bottom:1.5rem">Settings</h1>
    <div class="settings-grid">
      <nav class="settings-nav" id="settings-nav">
        <a href="#/settings?section=profile" class="settings-nav-item ${section === 'profile' ? 'active' : ''}">Profile</a>
        <a href="#/settings?section=account" class="settings-nav-item ${section === 'account' ? 'active' : ''}">Account</a>
        <a href="#/settings?section=appearance" class="settings-nav-item ${section === 'appearance' ? 'active' : ''}">Appearance</a>
        <a href="#/settings?section=integrations" class="settings-nav-item ${section === 'integrations' ? 'active' : ''}">Integrations</a>
        <a href="#/settings?section=export" class="settings-nav-item ${section === 'export' ? 'active' : ''}">Export Data</a>
        <a href="#/settings?section=danger" class="settings-nav-item ${section === 'danger' ? 'active' : ''}">Danger Zone</a>
      </nav>
      <div class="settings-content" id="settings-content"></div>
    </div>`;

  renderSettingsSection(section);
}

/**
 * Render a settings section
 */
function renderSettingsSection(section) {
  const content = $('#settings-content');
  if (!content) return;

  switch (section) {
    case 'profile': renderProfileSettings(content); break;
    case 'account': renderAccountSettings(content); break;
    case 'appearance': renderAppearanceSettings(content); break;
    case 'integrations': renderIntegrationSettings(content); break;
    case 'export': renderExportSettings(content); break;
    case 'danger': renderDangerZone(content); break;
    default: renderProfileSettings(content);
  }
}

/**
 * Profile settings
 */
async function renderProfileSettings(container) {
  const user = getCurrentUser();
  let profile = localStore.get('user_profile') || user || {};

  try {
    profile = await api.get('/user/profile');
    localStore.set('user_profile', profile);
  } catch {
    // Use cached profile
  }

  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem">Profile Settings</h2>
    <form id="profile-form">
      <div class="form-group">
        <label class="form-label">Display Name</label>
        <input type="text" class="form-input" id="profile-display-name" value="${profile.displayName || ''}" placeholder="Your display name">
      </div>
      <div class="form-group">
        <label class="form-label">Username</label>
        <input type="text" class="form-input" id="profile-username" value="${profile.username || ''}" placeholder="username" disabled>
        <small style="color:var(--text-muted)">Username cannot be changed</small>
      </div>
      <div class="form-group">
        <label class="form-label">Bio</label>
        <textarea class="form-textarea" id="profile-bio" rows="4" placeholder="Tell the world about yourself...">${profile.bio || ''}</textarea>
      </div>
      <div class="form-group">
        <label class="form-label">Website</label>
        <input type="url" class="form-input" id="profile-website" value="${profile.website || ''}" placeholder="https://yoursite.com">
      </div>
      <div class="form-group">
        <label class="form-label">Avatar URL</label>
        <div style="display:flex;gap:0.75rem;align-items:center">
          <div id="avatar-preview" style="width:64px;height:64px;border-radius:50%;overflow:hidden;border:2px solid var(--border);flex-shrink:0">
            ${profile.avatarUrl ? `<img src="${profile.avatarUrl}" style="width:100%;height:100%;object-fit:cover">` : ''}
          </div>
          <input type="text" class="form-input" id="profile-avatar" value="${profile.avatarUrl || ''}" placeholder="https://...">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Social Links</label>
        <input type="text" class="form-input" id="profile-twitter" value="${profile.social?.twitter || ''}" placeholder="Twitter handle" style="margin-bottom:0.5rem">
        <input type="text" class="form-input" id="profile-github" value="${profile.social?.github || ''}" placeholder="GitHub username">
      </div>
      <button type="submit" class="btn btn-primary">Save Profile</button>
    </form>`;

  // Avatar preview update
  $('#profile-avatar').addEventListener('input', (e) => {
    const preview = $('#avatar-preview');
    // BUG-102: Avatar URL rendered directly into innerHTML — can inject HTML (CWE-79, CVSS 5.5, HIGH, Tier 2)
    preview.innerHTML = e.target.value
      ? `<img src="${e.target.value}" style="width:100%;height:100%;object-fit:cover">`
      : '';
  });

  $('#profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const data = {
      displayName: $('#profile-display-name').value.trim(),
      bio: $('#profile-bio').value.trim(),
      website: $('#profile-website').value.trim(),
      avatarUrl: $('#profile-avatar').value.trim(),
      social: {
        twitter: $('#profile-twitter').value.trim(),
        github: $('#profile-github').value.trim()
      }
    };

    // BUG-103: Website URL not validated — can be javascript: URL displayed as link elsewhere (CWE-79, CVSS 5.0, MEDIUM, Tier 2)

    try {
      await api.put('/user/profile', data);
      localStore.set('user_profile', { ...profile, ...data });
      showToast('Profile updated!');
    } catch (error) {
      showToast(error.message || 'Failed to update profile', 'error');
    }
  });
}

/**
 * Account settings
 */
function renderAccountSettings(container) {
  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem">Account Settings</h2>
    <form id="email-form" style="margin-bottom:2rem">
      <h3 style="margin-bottom:1rem">Change Email</h3>
      <div class="form-group">
        <label class="form-label">New Email</label>
        <input type="email" class="form-input" id="new-email" placeholder="new@email.com" required>
      </div>
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input type="password" class="form-input" id="email-password" placeholder="Confirm with your password" required>
      </div>
      <button type="submit" class="btn btn-primary">Update Email</button>
    </form>
    <form id="password-form">
      <h3 style="margin-bottom:1rem">Change Password</h3>
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input type="password" class="form-input" id="current-password" required>
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input type="password" class="form-input" id="new-password" required>
      </div>
      <div class="form-group">
        <label class="form-label">Confirm New Password</label>
        <input type="password" class="form-input" id="confirm-password" required>
      </div>
      <button type="submit" class="btn btn-primary">Update Password</button>
    </form>
    <div style="margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)">
      <h3 style="margin-bottom:1rem">Active Sessions</h3>
      <div id="sessions-list"><div class="loading-overlay"><div class="spinner"></div></div></div>
    </div>`;

  $('#email-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('#new-email').value.trim();
    const password = $('#email-password').value;

    if (!isValidEmail(email)) {
      showToast('Invalid email address', 'error');
      return;
    }

    try {
      await api.put('/user/email', { email, password });
      showToast('Email updated. Please verify your new email.');
    } catch (error) {
      showToast(error.message || 'Failed to update email', 'error');
    }
  });

  $('#password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = $('#current-password').value;
    const newPassword = $('#new-password').value;
    const confirmPassword = $('#confirm-password').value;

    if (newPassword !== confirmPassword) {
      showToast('New passwords do not match', 'error');
      return;
    }

    try {
      await api.put('/user/password', { currentPassword, newPassword });
      showToast('Password updated!');
    } catch (error) {
      showToast(error.message || 'Failed to update password', 'error');
    }
  });

  // Load sessions
  loadSessions();
}

/**
 * Load active sessions
 */
async function loadSessions() {
  const container = $('#sessions-list');
  try {
    const data = await api.get('/user/sessions');
    const sessions = data.sessions || [];

    if (!sessions.length) {
      container.innerHTML = '<p style="color:var(--text-muted)">No active sessions</p>';
      return;
    }

    container.innerHTML = sessions.map(session => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:0.5rem">
        <div>
          <div style="font-weight:500">${session.device || 'Unknown Device'}</div>
          <div style="font-size:0.8125rem;color:var(--text-muted)">${session.ip} · ${session.location || 'Unknown'} · Last active ${session.lastActive}</div>
        </div>
        <button class="btn btn-sm btn-danger revoke-session" data-id="${session.id}">Revoke</button>
      </div>
    `).join('');

    $$('.revoke-session', container).forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api.delete(`/user/sessions/${btn.dataset.id}`);
          btn.closest('div').remove();
          showToast('Session revoked');
        } catch {
          showToast('Failed to revoke session', 'error');
        }
      });
    });
  } catch {
    container.innerHTML = '<p style="color:var(--text-muted)">Failed to load sessions</p>';
  }
}

/**
 * Appearance settings
 */
function renderAppearanceSettings(container) {
  const prefs = prefsStore.getAll();

  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem">Appearance</h2>
    <form id="appearance-form">
      <div class="form-group">
        <label class="form-label">Theme</label>
        <select class="form-select" id="pref-theme">
          <option value="light" ${prefs.theme === 'light' ? 'selected' : ''}>Light</option>
          <option value="dark" ${prefs.theme === 'dark' ? 'selected' : ''}>Dark</option>
          <option value="auto" ${prefs.theme === 'auto' ? 'selected' : ''}>System</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Editor Font</label>
        <select class="form-select" id="pref-editor-font">
          <option value="default" ${prefs.editorFont === 'default' ? 'selected' : ''}>System Default</option>
          <option value="serif" ${prefs.editorFont === 'serif' ? 'selected' : ''}>Serif</option>
          <option value="mono" ${prefs.editorFont === 'mono' ? 'selected' : ''}>Monospace</option>
        </select>
      </div>
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:0.5rem">
          <input type="checkbox" id="pref-autosave" ${prefs.autoSave ? 'checked' : ''}>
          Enable auto-save in editor
        </label>
      </div>
      <div class="form-group">
        <label class="form-label">Auto-save interval (seconds)</label>
        <input type="number" class="form-input" id="pref-autosave-interval" value="${prefs.autoSaveInterval / 1000}" min="5" max="300" style="max-width:120px">
      </div>
      <div class="form-group">
        <label class="form-label">Custom CSS</label>
        <textarea class="form-textarea" id="pref-custom-css" rows="6" placeholder="Add custom CSS styles...">${prefs.customCSS || ''}</textarea>
        <small style="color:var(--text-muted)">Custom styles applied to the entire page</small>
      </div>
      <button type="submit" class="btn btn-primary">Save Preferences</button>
    </form>`;

  $('#appearance-form').addEventListener('submit', (e) => {
    e.preventDefault();

    prefsStore.set('theme', $('#pref-theme').value);
    prefsStore.set('editorFont', $('#pref-editor-font').value);
    prefsStore.set('autoSave', $('#pref-autosave').checked);
    prefsStore.set('autoSaveInterval', parseInt($('#pref-autosave-interval').value) * 1000);

    // BUG-105: Custom CSS applied by injecting a <style> tag — CSS injection can exfiltrate data, deface UI, or execute via CSS expressions in older browsers (CWE-94, CVSS 5.5, TRICKY, Tier 1)
    const customCSS = $('#pref-custom-css').value;
    prefsStore.set('customCSS', customCSS);
    applyCustomCSS(customCSS);

    showToast('Preferences saved!');
  });
}

/**
 * Apply custom CSS
 */
function applyCustomCSS(css) {
  let styleEl = $('#custom-user-css');
  if (!styleEl) {
    styleEl = document.createElement('style');
    styleEl.id = 'custom-user-css';
    document.head.appendChild(styleEl);
  }
  // BUG-105 continued: CSS directly injected into style element
  styleEl.textContent = css;
}

/**
 * Integration settings
 */
function renderIntegrationSettings(container) {
  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem">Integrations</h2>
    <div class="card" style="margin-bottom:1rem">
      <div class="card-header">
        <h3>Webhook URL</h3>
      </div>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Receive notifications when posts are published.</p>
      <div class="form-group">
        <input type="url" class="form-input" id="webhook-url" placeholder="https://hooks.example.com/..." value="${localStore.get('webhook_url') || ''}">
      </div>
      <button class="btn btn-primary" id="save-webhook">Save Webhook</button>
      <button class="btn" id="test-webhook" style="margin-left:0.5rem">Test</button>
    </div>
    <div class="card" style="margin-bottom:1rem">
      <div class="card-header">
        <h3>API Token</h3>
      </div>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Use this token to access the API programmatically.</p>
      <div style="display:flex;gap:0.5rem">
        <input type="text" class="form-input" id="api-token-display" readonly value="${tokenStore.getToken() || 'No token available'}">
        <button class="btn" id="copy-token">Copy</button>
      </div>
    </div>
    <div class="card">
      <div class="card-header">
        <h3>Custom Script</h3>
      </div>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Add a custom script to your published pages (e.g., analytics).</p>
      <div class="form-group">
        <textarea class="form-textarea" id="custom-script" rows="5" placeholder="<script>...</script>">${localStore.get('custom_script') || ''}</textarea>
      </div>
      <button class="btn btn-primary" id="save-script">Save Script</button>
      <button class="btn" id="preview-script" style="margin-left:0.5rem">Preview</button>
    </div>`;

  $('#save-webhook').addEventListener('click', () => {
    const url = $('#webhook-url').value.trim();
    localStore.set('webhook_url', url);
    showToast('Webhook URL saved');
  });

  $('#test-webhook').addEventListener('click', async () => {
    const url = $('#webhook-url').value.trim();
    if (!url) return showToast('Enter a webhook URL first', 'error');
    try {
      // BUG-106: Webhook test sends to arbitrary user-provided URL — can be used for SSRF-like request (CWE-918, CVSS 4.5, MEDIUM, Tier 2)
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: 'test', timestamp: Date.now() })
      });
      showToast('Webhook test sent');
    } catch {
      showToast('Webhook test failed', 'error');
    }
  });

  $('#copy-token').addEventListener('click', () => {
    const input = $('#api-token-display');
    input.select();
    document.execCommand('copy');
    showToast('Token copied to clipboard');
  });

  $('#save-script').addEventListener('click', () => {
    const script = $('#custom-script').value;
    localStore.set('custom_script', script);
    showToast('Custom script saved');
  });

  $('#preview-script').addEventListener('click', () => {
    const script = $('#custom-script').value;
    // BUG-107: eval() on user-provided script content — direct code execution (CWE-95, CVSS 9.5, CRITICAL, Tier 1)
    try {
      eval(script);
      showToast('Script executed');
    } catch (error) {
      showToast(`Script error: ${error.message}`, 'error');
    }
  });
}

/**
 * Export data settings
 */
function renderExportSettings(container) {
  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem">Export Data</h2>
    <div class="card" style="margin-bottom:1rem">
      <h3 style="margin-bottom:0.75rem">Export Posts</h3>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Download all your posts as a JSON file.</p>
      <button class="btn btn-primary" id="export-posts">Export Posts</button>
    </div>
    <div class="card" style="margin-bottom:1rem">
      <h3 style="margin-bottom:0.75rem">Export All Data</h3>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Download all your data including posts, comments, settings, and profile.</p>
      <button class="btn btn-primary" id="export-all">Export All</button>
    </div>
    <div class="card">
      <h3 style="margin-bottom:0.75rem">Import Data</h3>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Import data from a JSON file.</p>
      <input type="file" id="import-file" accept=".json" class="form-input">
      <button class="btn btn-primary" id="import-btn" style="margin-top:0.5rem">Import</button>
    </div>`;

  $('#export-posts').addEventListener('click', async () => {
    try {
      const data = await api.get('/user/posts?all=true');
      downloadJSON(data, 'loomweaver-posts.json');
      showToast('Posts exported');
    } catch (error) {
      showToast('Export failed', 'error');
    }
  });

  $('#export-all').addEventListener('click', async () => {
    try {
      const data = await api.get('/user/export');
      downloadJSON(data, 'loomweaver-export.json');
    } catch (error) {
      showToast('Export failed', 'error');
    }
  });

  $('#import-btn').addEventListener('click', async () => {
    const fileInput = $('#import-file');
    const file = fileInput.files[0];
    if (!file) return showToast('Select a file first', 'error');

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const data = JSON.parse(e.target.result);
        // BUG-108: Imported JSON data merged into app config via prototype-pollution-vulnerable deepMerge (CWE-1321, CVSS 8.0, TRICKY, Tier 1)
        const config = localStore.get('app_config', {});
        deepMerge(config, data.config || {});
        localStore.set('app_config', config);

        if (data.posts) {
          await api.post('/user/import', { posts: data.posts });
        }

        showToast('Data imported successfully');
      } catch (error) {
        showToast('Import failed: ' + error.message, 'error');
      }
    };
    reader.readAsText(file);
  });
}

/**
 * Download JSON file
 */
function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Danger zone settings
 */
function renderDangerZone(container) {
  container.innerHTML = `
    <h2 style="margin-bottom:1.5rem;color:var(--danger)">Danger Zone</h2>
    <div class="card" style="border-color:var(--danger);margin-bottom:1rem">
      <h3>Delete All Posts</h3>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Permanently delete all your posts. This action cannot be undone.</p>
      <button class="btn btn-danger" id="delete-all-posts">Delete All Posts</button>
    </div>
    <div class="card" style="border-color:var(--danger)">
      <h3>Delete Account</h3>
      <p style="color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem">Permanently delete your account and all associated data.</p>
      <button class="btn btn-danger" id="delete-account">Delete Account</button>
    </div>`;

  $('#delete-all-posts').addEventListener('click', async () => {
    // BUG-109: Destructive action protected only by confirm() — no password re-confirmation (CWE-306, CVSS 5.0, MEDIUM, Tier 2)
    if (confirm('Are you absolutely sure? This will delete ALL your posts permanently.')) {
      try {
        await api.delete('/user/posts');
        showToast('All posts deleted');
      } catch (error) {
        showToast('Failed to delete posts', 'error');
      }
    }
  });

  $('#delete-account').addEventListener('click', async () => {
    if (confirm('This will permanently delete your account. Are you sure?')) {
      try {
        await api.delete('/user/account');
        logout();
        showToast('Account deleted');
      } catch (error) {
        showToast('Failed to delete account', 'error');
      }
    }
  });
}

/**
 * Initialize appearance from saved prefs
 */
export function initAppearance() {
  const prefs = prefsStore.getAll();

  // Apply theme
  if (prefs.theme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else if (prefs.theme === 'auto') {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
  }

  // Apply custom CSS from prefs
  // BUG-105 continued: Custom CSS loaded and applied on page load from localStorage
  if (prefs.customCSS) {
    applyCustomCSS(prefs.customCSS);
  }

  // Load and execute custom script
  const customScript = localStore.get('custom_script');
  if (customScript) {
    // BUG-107 continued: Custom script from localStorage executed on every page load
    try {
      eval(customScript);
    } catch (e) {
      console.warn('[Settings] Custom script error:', e);
    }
  }
}
