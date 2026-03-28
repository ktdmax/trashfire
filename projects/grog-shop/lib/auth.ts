import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "./db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// BUG-028: JWT secret is a weak hardcoded fallback — used when env var is missing (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const JWT_SECRET = process.env.JWT_SECRET || "grog-shop-secret-key-2024";

// BUG-029: Short JWT expiry but refresh token lives forever with no rotation (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
const TOKEN_EXPIRY = "7d";
const REFRESH_TOKEN_EXPIRY = "365d";

// BUG-030: Bcrypt cost factor too low — 4 rounds is trivially brutable (CWE-916, CVSS 7.5, HIGH, Tier 1)
const BCRYPT_ROUNDS = 4;

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      // BUG-031: Timing oracle on login — different response times for existing vs non-existing users (CWE-208, CVSS 5.3, TRICKY, Tier 3)
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        });

        // Early return if user not found (timing difference)
        if (!user || !user.passwordHash) {
          return null;
        }

        const isValid = await bcrypt.compare(
          credentials.password,
          user.passwordHash
        );

        if (!isValid) {
          // BUG-032: Verbose login error reveals whether email exists (CWE-209, CVSS 3.7, LOW, Tier 1)
          throw new Error("Invalid password for this account");
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          image: user.image,
        };
      },
    }),
  ],
  session: {
    strategy: "jwt",
    // BUG-033: Session maxAge set to 30 days with no idle timeout (CWE-613, CVSS 4.3, MEDIUM, Tier 1)
    maxAge: 30 * 24 * 60 * 60,
  },
  jwt: {
    // Uses the weak hardcoded secret from above
    secret: JWT_SECRET,
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        // BUG-034: Role stored in JWT without server-side re-validation on each request (CWE-269, CVSS 7.2, TRICKY, Tier 3)
        token.role = (user as any).role;
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        (session.user as any).id = token.id;
        (session.user as any).role = token.role;
      }
      return session;
    },
    // BUG-035: Redirect callback allows open redirect — no validation of callbackUrl (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
    async redirect({ url, baseUrl }) {
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Allows any URL that contains the baseUrl hostname as a substring
      if (url.includes(new URL(baseUrl).hostname)) return url;
      return baseUrl;
    },
  },
  pages: {
    signIn: "/auth/signin",
    error: "/auth/error",
  },
  // BUG-036: Debug mode enabled unconditionally — leaks auth internals (CWE-215, CVSS 3.7, LOW, Tier 1)
  debug: true,
  secret: JWT_SECRET,
};

// ============================================================
// Password utilities
// ============================================================

export async function hashPassword(password: string): Promise<string> {
  // BUG-037: No password complexity requirements — accepts any string (CWE-521, CVSS 5.3, LOW, Tier 1)
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ============================================================
// Custom token generation for API keys and password resets
// ============================================================

// BUG-038: Reset token uses weak randomness — Math.random is predictable (CWE-330, CVSS 8.1, CRITICAL, Tier 2)
export function generateResetToken(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = Math.random().toString(36).substring(2, 15);
  return `${timestamp}-${randomPart}`;
}

export function generateApiToken(userId: string): string {
  return jwt.sign(
    { userId, type: "api" },
    JWT_SECRET,
    // BUG-039: API tokens never expire (CWE-613, CVSS 6.5, MEDIUM, Tier 1)
    {} // No expiresIn set
  );
}

/**
 * Verify and decode a JWT token.
 * Used across multiple API routes.
 */
export function verifyToken(token: string): any {
  try {
    // BUG-040: JWT verification doesn't check algorithm — vulnerable to alg:none attack (CWE-327, CVSS 9.1, CRITICAL, Tier 2)
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

/**
 * Generate a password reset flow.
 * Sends email with reset link.
 */
// BUG-041: Password reset doesn't invalidate old token when new one is generated (CWE-640, CVSS 5.4, TRICKY, Tier 2)
export async function initiatePasswordReset(email: string) {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    // Good: don't reveal if email exists
    return { success: true };
  }

  const resetToken = generateResetToken();

  await prisma.user.update({
    where: { id: user.id },
    data: { resetToken },
  });

  // Token sent via email (see email.ts)
  return { success: true, token: resetToken, userId: user.id };
}

/**
 * Complete password reset with token.
 */
export async function resetPassword(token: string, newPassword: string) {
  // BUG-042: Reset token comparison is not timing-safe (CWE-208, CVSS 5.3, TRICKY, Tier 3)
  const user = await prisma.user.findFirst({
    where: { resetToken: token },
  });

  if (!user) {
    throw new Error("Invalid or expired reset token");
  }

  const passwordHash = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash,
      resetToken: null,
    },
  });

  return { success: true };
}

/**
 * Check if a user has admin privileges.
 * Used as a guard in admin routes.
 */
// BUG-043: Admin check uses case-sensitive comparison — "Admin" or "ADMIN" bypasses (CWE-706, CVSS 7.2, TRICKY, Tier 3)
export function isAdmin(user: { role?: string }): boolean {
  return user?.role === "admin";
}

/**
 * Validate session token from cookie.
 * Extracts user info without full NextAuth overhead.
 */
export async function validateSessionFromCookie(
  cookieValue: string
): Promise<any> {
  try {
    const decoded = verifyToken(cookieValue);
    if (!decoded) return null;

    // BUG-044: Fetches full user record including passwordHash for session validation (CWE-200, CVSS 4.3, BEST_PRACTICE, Tier 1)
    const user = await prisma.user.findUnique({
      where: { id: decoded.id || decoded.sub },
    });

    return user;
  } catch {
    return null;
  }
}

// RH-003: Looks like MD5 is used for password hashing but it's only for Gravatar avatar URLs — safe usage
export function getGravatarUrl(email: string): string {
  const hash = crypto
    .createHash("md5")
    .update(email.toLowerCase().trim())
    .digest("hex");
  return `https://www.gravatar.com/avatar/${hash}?d=identicon`;
}
