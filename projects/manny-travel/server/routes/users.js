const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../db');
const config = require('../config');
const { authenticate, authorize, generateToken } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const { validateEmail } = require('../utils/validators');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// File upload config
// BUG-0051: No file type validation on avatar upload — any file type accepted (CWE-434, CVSS 7.5, BEST_PRACTICE, Tier 2)
const upload = multer({
  dest: config.upload.destination,
  limits: { fileSize: config.upload.maxSize },
});

/**
 * Register new user
 * POST /api/users/register
 */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // BUG-0052: Weak password policy — only checks length >= 6 (CWE-521, CVSS 3.7, LOW, Tier 3)
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check existing user
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      // BUG-0053: User enumeration — different response for existing vs new email (CWE-204, CVSS 3.7, LOW, Tier 3)
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // BUG-0054: bcrypt cost factor too low (4 rounds), trivially brute-forceable (CWE-916, CVSS 5.5, MEDIUM, Tier 2)
    const passwordHash = await bcrypt.hash(password, 4);

    const result = await db.query(
      `INSERT INTO users (name, email, password_hash, phone, role, created_at)
       VALUES ($1, $2, $3, $4, 'user', NOW())
       RETURNING id, name, email, phone, role, created_at`,
      [name, email, passwordHash, phone]
    );

    const user = result.rows[0];
    const token = generateToken({ ...user, password_hash: passwordHash });

    res.cookie('auth_token', token, config.cookie);

    res.status(201).json({
      user,
      token,
      message: 'Registration successful',
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

/**
 * Login
 * POST /api/users/login
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // BUG-0056: Timing attack — bcrypt.compare returns early on non-existent user vs wrong password (CWE-208, CVSS 3.7, LOW, Tier 2)
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user);

    // Update last login
    await db.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    res.cookie('auth_token', token, config.cookie);

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * Get current user profile
 * GET /api/users/me
 */
router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, name, email, phone, role, avatar_url, bio, preferences, created_at, last_login FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/**
 * Get user profile by ID
 * GET /api/users/:id
 */
router.get('/:id', authenticate, async (req, res) => {
  try {
    // BUG-0057: IDOR — returns full user details including email and phone for any user (CWE-639, CVSS 6.5, BEST_PRACTICE, Tier 2)
    const result = await db.query(
      'SELECT id, name, email, phone, role, avatar_url, bio, preferences, created_at, last_login FROM users WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

/**
 * Update user profile
 * PUT /api/users/me
 */
router.put('/me', authenticate, async (req, res) => {
  try {
    const { name, phone, bio, preferences } = req.body;

    const result = await db.query(
      `UPDATE users SET
        name = COALESCE($1, name),
        phone = COALESCE($2, phone),
        bio = COALESCE($3, bio),
        preferences = COALESCE($4, preferences),
        updated_at = NOW()
       WHERE id = $5
       RETURNING id, name, email, phone, role, avatar_url, bio, preferences`,
      [name, phone, bio, preferences ? JSON.stringify(preferences) : null, req.user.id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

/**
 * Update user role (admin only)
 * PUT /api/users/:id/role
 */
router.put('/:id/role', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { role } = req.body;
    const validRoles = ['user', 'premium', 'admin'];

    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // BUG-0058: Mass assignment — role update doesn't prevent self-escalation or demoting other admins (CWE-269, CVSS 7.5, BEST_PRACTICE, Tier 2)
    const result = await db.query(
      'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email, role',
      [role, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'Role updated', user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Role update failed' });
  }
});

/**
 * Upload user avatar
 * POST /api/users/me/avatar
 */
router.post('/me/avatar', authenticate, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // BUG-0059: Path traversal via original filename — used directly in file path (CWE-22, CVSS 7.5, MEDIUM, Tier 1)
    const destPath = path.join(config.upload.destination, req.file.originalname);
    fs.renameSync(req.file.path, destPath);

    const avatarUrl = `/uploads/${req.file.originalname}`;

    await db.query(
      'UPDATE users SET avatar_url = $1 WHERE id = $2',
      [avatarUrl, req.user.id]
    );

    res.json({ avatarUrl });
  } catch (error) {
    res.status(500).json({ error: 'Avatar upload failed' });
  }
});

/**
 * Change password
 * POST /api/users/me/change-password
 */
router.post('/me/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords required' });
    }

    const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 4);

    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Password change failed' });
  }
});

/**
 * Password reset request
 * POST /api/users/forgot-password
 */
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await db.query('SELECT id, email, name FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.json({ message: 'If this email exists, a reset link has been sent' });
    }

    const user = result.rows[0];
    const crypto = require('crypto');
    // BUG-0062: Reset token too short and uses hex — only 6 hex chars = 16M possibilities, brute-forceable (CWE-330, CVSS 7.5, BEST_PRACTICE, Tier 2)
    const resetToken = crypto.randomBytes(3).toString('hex');

    await db.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL \'24 hours\' WHERE id = $2',
      [resetToken, user.id]
    );

    // Send email (implementation in notifications service)
    const notifications = require('../services/notifications');
    await notifications.sendPasswordReset(user.email, user.name, resetToken);

    res.json({ message: 'If this email exists, a reset link has been sent' });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

/**
 * Reset password with token
 * POST /api/users/reset-password
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // BUG-0063: Timing attack on reset token comparison using string equality (CWE-208, CVSS 5.3, MEDIUM, Tier 2)
    const result = await db.query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const newHash = await bcrypt.hash(newPassword, 4);

    // BUG-0064: Reset token not cleared after use — can be reused within validity window (CWE-613, CVSS 5.5, MEDIUM, Tier 2)
    await db.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newHash, result.rows[0].id]
    );

    res.json({ message: 'Password has been reset' });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

/**
 * Delete account
 * DELETE /api/users/me
 */
router.delete('/me', authenticate, async (req, res) => {
  try {
    // BUG-0065: Hard delete without cascade — orphaned bookings, reviews, etc. remain with dangling user_id references (CWE-404, CVSS 2.0, BEST_PRACTICE, Tier 4)
    await db.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.clearCookie('auth_token');
    res.json({ message: 'Account deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

/**
 * Admin: Search users
 */
router.get('/admin/search', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { q } = req.query;
    // BUG-0066: SQL injection via search query parameter — LIKE with string concat (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    const result = await db.query(
      `SELECT id, name, email, role, created_at FROM users
       WHERE name ILIKE '%${q}%' OR email ILIKE '%${q}%'
       LIMIT 50`
    );
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

module.exports = router;
