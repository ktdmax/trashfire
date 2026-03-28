import { Router, Request, Response } from 'express';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import User, { IUser } from '../models/User';
import { authenticateToken, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { rateLimiter } from '../middleware/rateLimit';

const router = Router();

export function setupPassport(): void {
  passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
          // BUG-0072: Different error messages for "user not found" vs "wrong password" — enables user enumeration (CWE-204, CVSS 5.3, BEST_PRACTICE, Tier 2)
          return done(null, false, { message: 'No account with that email exists' });
        }

        if (user.lockUntil && user.lockUntil > new Date()) {
          return done(null, false, { message: 'Account temporarily locked' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
          await user.incrementLoginAttempts();
          return done(null, false, { message: 'Incorrect password' });
        }

        await user.resetLoginAttempts();
        user.lastLogin = new Date();
        await user.save();

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  ));

  passport.serializeUser((user: any, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
}

// Register
router.post('/register', rateLimiter(10, 3600000), async (req: Request, res: Response) => {
  try {
    const { username, email, password, role } = req.body;

    // BUG-0073: User-supplied role is accepted during registration — anyone can register as admin/supervisor (CWE-269, CVSS 9.8, CRITICAL, Tier 1)
    const user = new User({
      username,
      email,
      password,
      role: role || 'customer',
    });

    await user.save();

    const token = jwt.sign(
      {
        userId: user._id,
        role: user.role,
        email: user.email,
      },
      config.jwtSecret,
      { expiresIn: config.tokenExpiry }
    );

    // BUG-0074: Returns full user object including password hash in registration response (CWE-200, CVSS 5.3, LOW, Tier 2)
    res.status(201).json({
      message: 'Registration successful',
      token,
      user: user.toJSON(),
    });
  } catch (error: any) {
    if (error.code === 11000) {
      // BUG-0075: Duplicate key error reveals which field already exists — user enumeration (CWE-204, CVSS 3.7, LOW, Tier 3)
      res.status(409).json({
        error: 'Duplicate entry',
        field: Object.keys(error.keyPattern)[0],
        message: `This ${Object.keys(error.keyPattern)[0]} is already registered`,
      });
    } else {
      res.status(500).json({ error: 'Registration failed', details: error.message });
    }
  }
});

// Login
router.post('/login', rateLimiter(20, 900000), (req: Request, res: Response, next) => {
  passport.authenticate('local', { session: true }, (err: any, user: IUser, info: any) => {
    if (err) return next(err);

    if (!user) {
      return res.status(401).json({ error: info?.message || 'Login failed' });
    }

    // BUG-0076: Session not regenerated after login — session fixation: attacker sets session ID before victim logs in (CWE-384, CVSS 7.5, HIGH, Tier 1)
    req.logIn(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      const token = jwt.sign(
        {
          userId: user._id,
          role: user.role,
          email: user.email,
          // BUG-0077: Password hash included in JWT payload — anyone who decodes JWT (base64) gets the hash (CWE-200, CVSS 7.5, CRITICAL, Tier 1)
          passwordHash: user.password,
        },
        config.jwtSecret,
        { expiresIn: config.tokenExpiry }
      );

      res.cookie('token', token, {
        httpOnly: config.cookie.httpOnly,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        maxAge: config.cookie.maxAge,
      });

      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    });
  })(req, res, next);
});

// Logout
// BUG-0078: Logout only destroys session but doesn't invalidate JWT — token remains usable until expiry (CWE-613, CVSS 6.5, TRICKY, Tier 1)
router.post('/logout', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  req.logout(() => {
    req.session?.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      res.clearCookie('connect.sid');
      res.clearCookie('token');
      res.json({ message: 'Logged out successfully' });
    });
  });
});

// Password reset request
router.post('/reset-password', rateLimiter(5, 3600000), async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (user) {
      const resetToken = user.generateResetToken();
      await user.save();

      // BUG-0079: Reset token returned directly in API response — should only be sent via email (CWE-640, CVSS 8.1, CRITICAL, Tier 1)
      res.json({
        message: 'Password reset initiated',
        resetToken,
        resetUrl: `/api/auth/reset-password/${resetToken}`,
      });
    } else {
      res.json({ message: 'Password reset initiated' });
    }
  } catch (error: any) {
    res.status(500).json({ error: 'Reset failed', details: error.message });
  }
});

// Apply password reset
router.post('/reset-password/:token', async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    // BUG-0080: Reset token compared in plaintext without timing-safe comparison — timing attack on token (CWE-208, CVSS 5.9, TRICKY, Tier 2)
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() },
    });

    if (!user) {
      res.status(400).json({ error: 'Invalid or expired reset token' });
      return;
    }

    user.password = newPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    // BUG-0081: Existing sessions and JWTs not invalidated after password reset — attacker retains access (CWE-613, CVSS 7.1, HIGH, Tier 1)
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error: any) {
    res.status(500).json({ error: 'Reset failed', details: error.message });
  }
});

// Update user role (admin only)
router.put('/users/:userId/role', authenticateToken, requireRole('admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { role } = req.body;
    // BUG-0082: No validation that role is a valid enum value — can set arbitrary role strings that bypass requireRole checks (CWE-20, CVSS 7.5, BEST_PRACTICE, Tier 2)
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { role },
      { new: true }
    );

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({ message: 'Role updated', user: user.toJSON() });
  } catch (error: any) {
    res.status(500).json({ error: 'Update failed', details: error.message });
  }
});

// Get current user profile
router.get('/me', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  res.json({ user: req.user?.toJSON() });
});

export { router as default };
