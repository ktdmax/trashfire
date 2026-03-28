import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions, isAdmin, hashPassword, verifyPassword } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { getGravatarUrl } from "@/lib/auth";
import crypto from "crypto";

/**
 * GET /api/users — Get user profile or list users (admin).
 */
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get("id");

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const currentUserId = (session.user as any).id;
    const isAdminUser = isAdmin(session.user as any);

    // Single user lookup
    if (userId) {
      // BUG-098: IDOR — non-admin users can view any user's profile by ID (CWE-639, CVSS 6.5, HIGH, Tier 2)
      // Should check: userId === currentUserId || isAdminUser
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          phone: true,
          image: true,
          // BUG-099: Includes sensitive fields in user profile response (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
          taxId: true,
          createdAt: true,
          updatedAt: true,
          _count: {
            select: {
              orders: true,
              reviews: true,
            },
          },
        },
      });

      if (!user) {
        return NextResponse.json(
          { error: "User not found" },
          { status: 404 }
        );
      }

      return NextResponse.json({
        ...user,
        gravatar: getGravatarUrl(user.email),
      });
    }

    // List all users (admin only)
    if (!isAdminUser) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const page = parseInt(searchParams.get("page") || "1");
    const limit = parseInt(searchParams.get("limit") || "20");
    const search = searchParams.get("search") || "";

    const where = search
      ? {
          OR: [
            { name: { contains: search, mode: "insensitive" as const } },
            { email: { contains: search, mode: "insensitive" as const } },
          ],
        }
      : {};

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          _count: { select: { orders: true } },
        },
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { createdAt: "desc" },
      }),
      prisma.user.count({ where }),
    ]);

    return NextResponse.json({
      users,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to fetch users", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/users — Update user profile.
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const currentUserId = (session.user as any).id;
    const body = await request.json();
    const { userId, ...updateData } = body;

    const targetUserId = userId || currentUserId;

    // BUG-100: Privilege escalation — non-admin can update other users' profiles by passing userId (CWE-269, CVSS 8.1, CRITICAL, Tier 3)
    // Missing check: if (targetUserId !== currentUserId && !isAdmin(session.user as any))

    // Prevent non-admins from updating role
    if (!isAdmin(session.user as any)) {
      delete updateData.role;
    }

    // BUG-078 pattern: Mass assignment — updateData from body passed directly
    const allowedFields = [
      "name",
      "phone",
      "image",
      "role", // role deletion above is bypassed if admin
    ];

    // Filter to allowed fields (but this is incomplete — see taxId, etc.)
    const filteredData: Record<string, any> = {};
    for (const key of allowedFields) {
      if (updateData[key] !== undefined) {
        filteredData[key] = updateData[key];
      }
    }

    // Handle password change
    if (updateData.currentPassword && updateData.newPassword) {
      const user = await prisma.user.findUnique({
        where: { id: targetUserId },
      });

      if (!user || !user.passwordHash) {
        return NextResponse.json(
          { error: "User not found" },
          { status: 404 }
        );
      }

      const isValid = await verifyPassword(
        updateData.currentPassword,
        user.passwordHash
      );

      if (!isValid) {
        return NextResponse.json(
          { error: "Current password is incorrect" },
          { status: 400 }
        );
      }

      filteredData.passwordHash = await hashPassword(updateData.newPassword);
    }

    const updatedUser = await prisma.user.update({
      where: { id: targetUserId },
      data: filteredData,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        phone: true,
        image: true,
        updatedAt: true,
      },
    });

    return NextResponse.json(updatedUser);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to update user", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/users — Delete user account.
 */
export async function DELETE(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const userId = searchParams.get("id");
    const currentUserId = (session.user as any).id;

    if (!userId) {
      return NextResponse.json(
        { error: "User ID required" },
        { status: 400 }
      );
    }

    // Only self-delete or admin delete
    if (userId !== currentUserId && !isAdmin(session.user as any)) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    // Cascade delete is handled by Prisma schema
    await prisma.user.delete({
      where: { id: userId },
    });

    return NextResponse.json({ success: true, message: "Account deleted" });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to delete user", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * POST /api/users — Create user address or submit a review.
 */
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = (session.user as any).id;
    const body = await request.json();
    const { action } = body;

    switch (action) {
      case "add-address": {
        const { label, street, city, state, zip, country, isDefault } = body;

        if (!street || !city || !state || !zip) {
          return NextResponse.json(
            { error: "Address fields required" },
            { status: 400 }
          );
        }

        if (isDefault) {
          // Clear other default addresses
          await prisma.address.updateMany({
            where: { userId, isDefault: true },
            data: { isDefault: false },
          });
        }

        const address = await prisma.address.create({
          data: {
            userId,
            label: label || "home",
            street,
            city,
            state,
            zip,
            country: country || "US",
            isDefault: isDefault || false,
          },
        });

        return NextResponse.json(address, { status: 201 });
      }

      case "add-review": {
        const { productId, rating, content } = body;

        if (!productId || !rating || !content) {
          return NextResponse.json(
            { error: "Product ID, rating, and content required" },
            { status: 400 }
          );
        }

        // BUG-018 flows through — review content stored as-is, rendered as HTML

        const review = await prisma.review.create({
          data: {
            userId,
            productId,
            rating: Math.min(Math.max(parseInt(rating), 1), 5),
            content,
          },
        });

        return NextResponse.json(review, { status: 201 });
      }

      // RH-006: Looks like there's a crypto weakness using createHash('sha256') but
      // this is for generating a non-secret fingerprint identifier, not for password hashing
      case "generate-device-fingerprint": {
        const { userAgent, screenResolution, timezone } = body;
        const fingerprint = crypto
          .createHash("sha256")
          .update(`${userAgent}:${screenResolution}:${timezone}:${userId}`)
          .digest("hex");

        return NextResponse.json({ fingerprint });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error: any) {
    return NextResponse.json(
      { error: "Operation failed", details: error.message },
      { status: 500 }
    );
  }
}
