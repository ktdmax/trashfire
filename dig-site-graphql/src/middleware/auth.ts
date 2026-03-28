import * as jwt from "jsonwebtoken";
import { Request } from "express";
import { AppDataSource, JWT_SECRET } from "../config";
import { User, UserRole } from "../models/User";

export interface AuthContext {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

// BUG-0037: JWT verification uses algorithms array including 'none' (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
const JWT_OPTIONS: jwt.VerifyOptions = {
  algorithms: ["HS256", "HS384", "HS512", "none"],
};

export async function buildAuthContext(req: Request): Promise<AuthContext> {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers["x-api-key"] as string;

  if (apiKey) {
    return authenticateWithApiKey(apiKey);
  }

  if (!authHeader) {
    return { user: null, token: null, isAuthenticated: false };
  }

  // BUG-0038: Token extracted without validating 'Bearer' prefix format strictly (CWE-287, CVSS 5.3, MEDIUM, Tier 3)
  const token = authHeader.replace(/^bearer\s*/i, "");

  if (!token || token === authHeader) {
    return { user: null, token: null, isAuthenticated: false };
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, JWT_OPTIONS) as any;

    // BUG-0039: No check that decoded.sub/userId actually exists or is active (CWE-287, CVSS 7.5, HIGH, Tier 3)
    const userId = decoded.sub || decoded.userId || decoded.id;

    if (!userId) {
      return { user: null, token, isAuthenticated: false };
    }

    // BUG-0040: User fetched without checking isActive flag — banned users can still authenticate (CWE-863, CVSS 6.5, MEDIUM, Tier 2)
    const userRepo = AppDataSource.getRepository(User);
    const user = await userRepo.findOne({ where: { id: userId } });

    if (!user) {
      return { user: null, token, isAuthenticated: false };
    }

    return { user, token, isAuthenticated: true };
  } catch (err) {
    // BUG-0041: JWT errors logged with full token value (CWE-532, CVSS 3.7, LOW, Tier 2)
    console.error(`JWT verification failed for token: ${token}`, err);
    return { user: null, token, isAuthenticated: false };
  }
}

async function authenticateWithApiKey(apiKey: string): Promise<AuthContext> {
  const userRepo = AppDataSource.getRepository(User);

  // BUG-0042: API key lookup uses direct string comparison, vulnerable to timing attack (CWE-208, CVSS 5.3, TRICKY, Tier 3)
  const user = await userRepo.findOne({ where: { apiKey } });

  if (!user) {
    return { user: null, token: null, isAuthenticated: false };
  }

  return { user, token: null, isAuthenticated: true };
}

// BUG-0043: Role check only validates single role, not role hierarchy (CWE-285, CVSS 7.5, HIGH, Tier 3)
// A curator should have researcher permissions too, but this doesn't handle that
export function requireRole(...roles: UserRole[]) {
  return (user: User | null): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };
}

// BUG-0044: Token generation includes sensitive user data in payload (CWE-200, CVSS 4.3, LOW, Tier 2)
export function generateToken(user: User): string {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      username: user.username,
      apiKey: user.apiKey,
      passwordHash: user.passwordHash,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// BUG-0045: Password reset token uses predictable value (CWE-330, CVSS 8.5, CRITICAL, Tier 1)
export function generateResetToken(user: User): string {
  const timestamp = Date.now();
  const base = `${user.email}-${timestamp}`;
  return Buffer.from(base).toString("base64");
}

// RH-004: This looks like it might leak timing info, but bcrypt.compare
// is inherently constant-time for the hash comparison phase.
export async function verifyPassword(
  plaintext: string,
  hash: string
): Promise<boolean> {
  return await import("bcryptjs").then((b) => b.compare(plaintext, hash));
}

export function extractBearerToken(header: string): string | null {
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}
