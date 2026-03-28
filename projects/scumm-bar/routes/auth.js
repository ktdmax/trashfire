const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { generateToken, hashResetToken } = require('../utils/helpers');

// BUG-043: No rate limiting on login endpoint — brute force possible (CWE-307, CVSS 5.3, LOW, Tier 1)

// POST /auth/register
router.post('/register', async (req, res) => {
  try {
    // BUG-044: Mass assignment — role, loyaltyPoints, isActive all settable from request body (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
    const userData = req.body;

    // Check if user exists
    const existing = await User.findOne({ email: userData.email });
    if (existing) {
      // BUG-045: User enumeration — different messages for existing vs non-existing email (CWE-204, CVSS 3.7, LOW, Tier 1)
      return res.status(400).json({ error: 'An account with this email already exists' });
    }

    const user = new User(userData);
    await user.save();

    // BUG-046: Session fixation — session not regenerated after registration/login (CWE-384, CVSS 7.5, HIGH, Tier 2)
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.username = user.username;

    res.status(201).json({
      message: 'Registration successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        loyaltyPoints: user.loyaltyPoints,
      },
    });
  } catch (err) {
    // BUG-047: Verbose error reveals MongoDB validation details (CWE-209, CVSS 3.5, LOW, Tier 1)
    res.status(500).json({ error: err.message, details: err.errors });
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // BUG-048: NoSQL injection — if username is {$gt: ""}, it matches first user (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
    // The findByCredentials static passes username directly to findOne
    const user = await User.findByCredentials(username, password);

    if (!user) {
      // BUG-049: Timing difference reveals whether username exists (CWE-208, CVSS 3.7, TRICKY, Tier 3)
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Session fixation: no session.regenerate() call
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.username = user.username;

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        loyaltyPoints: user.loyaltyPoints,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    // BUG-050: Cookie not cleared on logout — session cookie persists (CWE-613, CVSS 4.3, MEDIUM, Tier 1)
    res.json({ message: 'Logged out' });
  });
});

// POST /auth/forgot-password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // BUG-051: User enumeration via forgot password — different response for valid vs invalid email (CWE-204, CVSS 3.7, LOW, Tier 1)
      return res.status(404).json({ error: 'No account found with that email' });
    }

    // BUG-052: Reset token is predictable — uses Math.random (CWE-330, CVSS 7.5, CRITICAL, Tier 1)
    const resetToken = Math.random().toString(36).substring(2, 15);
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    // BUG-053: Reset token returned in response — defeats purpose of email verification (CWE-640, CVSS 8.1, CRITICAL, Tier 1)
    res.json({
      message: 'Password reset token generated',
      resetToken: resetToken,
      expiresIn: '24 hours',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /auth/reset-password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // BUG-054: NoSQL injection on resetToken — can pass {$ne: null} to match any user with a token (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // BUG-055: No password complexity requirements on reset (CWE-521, CVSS 5.3, MEDIUM, Tier 1)
    user.password = newPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /auth/profile
router.get('/profile', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // BUG-056: Returns full user object including password hash (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
    const user = await User.findById(req.session.userId);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /auth/profile
router.put('/profile', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // BUG-057: Mass assignment on profile update — user can change role, loyaltyPoints (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
    const user = await User.findByIdAndUpdate(
      req.session.userId,
      req.body,
      { new: true, runValidators: true }
    );
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
