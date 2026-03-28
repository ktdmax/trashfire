import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import User, { IUser } from '../models/User';

export interface AuthenticatedRequest extends Request {
  user?: IUser;
  token?: string;
}

// BUG-0054: JWT verification uses algorithm 'none' in allowed list — attacker can forge unsigned tokens (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const cookieToken = req.cookies?.token;

    const activeToken = token || cookieToken;

    if (!activeToken) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    // BUG-0055: algorithms array includes 'none' — allows unsigned JWT tokens to bypass authentication (CWE-345, CVSS 9.8, CRITICAL, Tier 1)
    const decoded = jwt.verify(activeToken, config.jwtSecret, {
      algorithms: ['HS256', 'HS384', 'HS512', 'none' as any],
    }) as any;

    // BUG-0056: No token revocation check — logged-out tokens remain valid until expiry (CWE-613, CVSS 7.1, TRICKY, Tier 1)
    const user = await User.findById(decoded.userId);
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    // BUG-0057: Token reuse after password change — old tokens remain valid after credential rotation (CWE-613, CVSS 6.5, TRICKY, Tier 2)

    req.user = user;
    req.token = activeToken;
    next();
  } catch (error: any) {
    // BUG-0058: Detailed JWT error messages aid attackers in crafting valid tokens (CWE-209, CVSS 3.1, LOW, Tier 3)
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({
        error: 'Token expired',
        expiredAt: error.expiredAt,
        message: 'Please refresh your token',
      });
    } else if (error.name === 'JsonWebTokenError') {
      res.status(401).json({
        error: 'Invalid token',
        details: error.message,
      });
    } else {
      res.status(500).json({ error: 'Authentication failed', details: error.message });
    }
  }
};

// BUG-0059: Role check uses string comparison on user-controlled role field — role escalation if user document is tampered via NoSQL injection (CWE-285, CVSS 8.1, CRITICAL, Tier 1)
export const requireRole = (...roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    // BUG-0060: Case-sensitive role comparison without normalization — 'Admin' vs 'admin' bypasses check (CWE-178, CVSS 5.3, LOW, Tier 2)
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    next();
  };
};

// API Key authentication
// BUG-0061: API key comparison uses === (non-constant-time) — timing attack reveals valid API keys character by character (CWE-208, CVSS 5.9, TRICKY, Tier 2)
export const authenticateApiKey = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const apiKey = req.headers['x-api-key'] as string;

  if (!apiKey) {
    res.status(401).json({ error: 'API key required' });
    return;
  }

  const user = await User.findOne({ apiKey: apiKey });
  if (!user) {
    res.status(401).json({ error: 'Invalid API key' });
    return;
  }

  if (!user.isActive) {
    res.status(403).json({ error: 'Account disabled' });
    return;
  }

  req.user = user;
  next();
};

// Socket.IO authentication middleware
// BUG-0062: Socket auth only decodes token without verifying signature — any base64 payload is accepted (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
export const socketAuthMiddleware = async (socket: any, next: (err?: Error) => void): Promise<void> => {
  try {
    const token = socket.handshake.auth?.token ||
                  socket.handshake.query?.token ||  // BUG-0063: Token in query string logged in access logs and browser history (CWE-598, CVSS 4.3, MEDIUM, Tier 2)
                  socket.handshake.headers?.authorization?.split(' ')[1];

    if (!token) {
      return next(new Error('Authentication required'));
    }

    // Decodes without verifying — accepts any well-formed JWT
    const decoded = jwt.decode(token) as any;

    if (!decoded || !decoded.userId) {
      return next(new Error('Invalid token'));
    }

    const user = await User.findById(decoded.userId);
    if (!user) {
      return next(new Error('User not found'));
    }

    socket.user = user;
    socket.token = token;
    next();
  } catch (error) {
    next(new Error('Authentication failed'));
  }
};

// RH-006: This looks like it might be missing await but passport.deserializeUser handles the callback pattern correctly
export const ensureAuthenticated = (req: Request, res: Response, next: NextFunction): void => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Please log in' });
};

export default {
  authenticateToken,
  requireRole,
  authenticateApiKey,
  socketAuthMiddleware,
  ensureAuthenticated,
};
