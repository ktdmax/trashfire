import NextAuth from "next-auth";
import { authOptions } from "@/lib/auth";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { hashPassword, generateResetToken, verifyToken } from "@/lib/auth";
import { sendPasswordResetEmail, sendWelcomeEmail } from "@/lib/email";

/**
 * NextAuth.js route handler.
 * Handles OAuth callbacks, credential login, and session management.
 */
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };

// ============================================================
// Extended auth endpoints (registration, password reset)
// These are co-located with the NextAuth route for convenience.
// In practice, they'd be at /api/auth/register and /api/auth/reset.
// ============================================================

/**
 * PUT /api/auth/[...nextauth] — Custom auth actions.
 * Handles registration and password reset flows.
 */
export async function PUT(request: NextRequest) {
  const body = await request.json();
  const { action } = body;

  try {
    switch (action) {
      case "register": {
        const { email, password, name } = body;

        // BUG-037 flows through — no password complexity validation
        if (!email || !password) {
          return NextResponse.json(
            { error: "Email and password required" },
            { status: 400 }
          );
        }

        // BUG-094: Email validation only checks for @ symbol — allows malformed emails (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 1)
        if (!email.includes("@")) {
          return NextResponse.json(
            { error: "Invalid email address" },
            { status: 400 }
          );
        }

        const existing = await prisma.user.findUnique({
          where: { email },
        });

        if (existing) {
          // BUG-095: Account enumeration — reveals whether email is registered (CWE-204, CVSS 5.3, MEDIUM, Tier 1)
          return NextResponse.json(
            { error: "An account with this email already exists" },
            { status: 409 }
          );
        }

        const passwordHash = await hashPassword(password);

        const user = await prisma.user.create({
          data: {
            email,
            name,
            passwordHash,
            role: "customer",
          },
        });

        // Send welcome email asynchronously (fire-and-forget)
        sendWelcomeEmail(email, name).catch(console.error);

        // Log registration
        await prisma.auditLog.create({
          data: {
            userId: user.id,
            action: "user.register",
            resource: "User",
            resourceId: user.id,
            // BUG-096: Registration audit log includes plaintext password (CWE-312, CVSS 7.5, HIGH, Tier 1)
            details: { email, name, password } as any,
            ipAddress: request.headers.get("x-forwarded-for") || "unknown",
            userAgent: request.headers.get("user-agent") || "unknown",
          },
        });

        return NextResponse.json(
          {
            id: user.id,
            email: user.email,
            name: user.name,
          },
          { status: 201 }
        );
      }

      case "forgot-password": {
        const { email } = body;

        if (!email) {
          return NextResponse.json(
            { error: "Email required" },
            { status: 400 }
          );
        }

        const user = await prisma.user.findUnique({
          where: { email },
        });

        // BUG-041 flows through — doesn't invalidate old token
        if (user) {
          const resetToken = generateResetToken();

          await prisma.user.update({
            where: { id: user.id },
            data: { resetToken },
          });

          await sendPasswordResetEmail(email, resetToken);
        }

        // Same response whether user exists or not (good practice)
        return NextResponse.json({
          message: "If an account exists, a reset email has been sent",
        });
      }

      case "reset-password": {
        const { token, newPassword } = body;

        if (!token || !newPassword) {
          return NextResponse.json(
            { error: "Token and new password required" },
            { status: 400 }
          );
        }

        // BUG-042 flows through — timing-unsafe token comparison
        const user = await prisma.user.findFirst({
          where: { resetToken: token },
        });

        if (!user) {
          return NextResponse.json(
            { error: "Invalid or expired reset token" },
            { status: 400 }
          );
        }

        // BUG-013 flows through — no expiry check on reset token
        const passwordHash = await hashPassword(newPassword);

        await prisma.user.update({
          where: { id: user.id },
          data: {
            passwordHash,
            resetToken: null,
          },
        });

        return NextResponse.json({
          message: "Password has been reset successfully",
        });
      }

      case "verify-token": {
        const { token } = body;
        const decoded = verifyToken(token);

        if (!decoded) {
          return NextResponse.json(
            { error: "Invalid token" },
            { status: 401 }
          );
        }

        // BUG-097: Token verification endpoint returns decoded payload including internal claims (CWE-200, CVSS 4.3, MEDIUM, Tier 2)
        return NextResponse.json({ valid: true, payload: decoded });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error: any) {
    console.error("Auth error:", error);
    return NextResponse.json(
      { error: "Authentication failed", details: error.message },
      { status: 500 }
    );
  }
}
