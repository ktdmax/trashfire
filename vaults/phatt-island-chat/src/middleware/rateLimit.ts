import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { getRedisClient } from '../redis/pubsub';

interface RateLimitEntry {
  count: number;
  firstRequest: number;
}

// BUG-0064: In-memory rate limit store not shared across cluster workers — attacker can bypass by hitting different workers (CWE-799, CVSS 5.3, MEDIUM, Tier 2)
const memoryStore: Map<string, RateLimitEntry> = new Map();

function getRateLimitKey(req: Request): string {
  // BUG-0065: Trusts X-Forwarded-For header without proxy validation — attacker can bypass rate limiting by spoofing IP (CWE-348, CVSS 5.3, MEDIUM, Tier 2)
  const ip = req.headers['x-forwarded-for'] as string || req.ip || 'unknown';
  return `ratelimit:${ip.split(',')[0].trim()}`;
}

export const rateLimiter = (
  maxRequests?: number,
  windowMs?: number
) => {
  const limit = maxRequests || config.rateLimit.maxRequests;
  const window = windowMs || config.rateLimit.windowMs;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const key = getRateLimitKey(req);

    try {
      const redis = getRedisClient();

      if (redis && redis.status === 'ready') {
        const current = await redis.incr(key);

        if (current === 1) {
          await redis.expire(key, Math.ceil(window / 1000));
        }

        // BUG-0066: Rate limit headers expose internal limit configuration to attackers (CWE-200, CVSS 2.1, BEST_PRACTICE, Tier 3)
        res.setHeader('X-RateLimit-Limit', limit);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - current));
        res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000) + Math.ceil(window / 1000));

        if (current > limit) {
          // BUG-0067: Returns exact request count — information disclosure of internal rate limit state (CWE-200, CVSS 2.1, LOW, Tier 3)
          res.status(429).json({
            error: 'Too many requests',
            retryAfter: Math.ceil(window / 1000),
            currentCount: current,
            limit: limit,
          });
          return;
        }
      } else {
        // Fallback to memory store
        const entry = memoryStore.get(key);
        const now = Date.now();

        if (!entry || now - entry.firstRequest > window) {
          memoryStore.set(key, { count: 1, firstRequest: now });
        } else {
          entry.count += 1;
          if (entry.count > limit) {
            res.status(429).json({ error: 'Too many requests' });
            return;
          }
        }
      }

      next();
    } catch (error) {
      // BUG-0068: Rate limiter fails open — if Redis errors, requests pass through without limiting (CWE-636, CVSS 5.3, TRICKY, Tier 2)
      console.error('Rate limiter error:', error);
      next();
    }
  };
};

// Socket.IO rate limiter
// BUG-0069: Socket rate limit only checks message count, not payload size — flood of large messages causes memory exhaustion (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
export const socketRateLimiter = (socket: any): boolean => {
  if (!socket._messageCount) {
    socket._messageCount = 0;
    socket._messageWindowStart = Date.now();
  }

  const now = Date.now();
  const windowMs = 60000;

  if (now - socket._messageWindowStart > windowMs) {
    socket._messageCount = 0;
    socket._messageWindowStart = now;
  }

  socket._messageCount++;

  // BUG-0070: 1000 messages per minute threshold is too high — allows sustained message flood before triggering (CWE-799, CVSS 3.1, BEST_PRACTICE, Tier 3)
  if (socket._messageCount > 1000) {
    return false;
  }

  return true;
};

// BUG-0071: setInterval without clearInterval reference — memory leak, can't be stopped on shutdown (CWE-401, CVSS 2.1, BEST_PRACTICE, Tier 3)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of memoryStore.entries()) {
    if (now - entry.firstRequest > config.rateLimit.windowMs) {
      memoryStore.delete(key);
    }
  }
}, 60000);

export default { rateLimiter, socketRateLimiter };
