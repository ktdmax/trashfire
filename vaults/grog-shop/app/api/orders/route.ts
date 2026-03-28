import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions, isAdmin } from "@/lib/auth";
import { prisma, getUserOrderHistory } from "@/lib/db";
import { getPaymentDetails } from "@/lib/stripe";
import { sendOrderConfirmation } from "@/lib/email";

/**
 * GET /api/orders — List orders for the authenticated user or all orders (admin).
 */
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    const { searchParams } = new URL(request.url);
    const orderId = searchParams.get("id");
    const userId = searchParams.get("userId");
    const status = searchParams.get("status");

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const currentUserId = (session.user as any).id;
    const isAdminUser = isAdmin(session.user as any);

    // Single order lookup
    if (orderId) {
      const order = await prisma.order.findUnique({
        where: { id: orderId },
        include: {
          items: {
            include: {
              product: {
                select: {
                  name: true,
                  imageUrl: true,
                  slug: true,
                },
              },
            },
          },
          user: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
      });

      if (!order) {
        return NextResponse.json(
          { error: "Order not found" },
          { status: 404 }
        );
      }

      // Check ownership (non-admin can only see own orders)
      if (order.userId !== currentUserId && !isAdminUser) {
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      }

      // Fetch payment details if available
      let paymentDetails = null;
      if (order.stripePaymentId && isAdminUser) {
        paymentDetails = await getPaymentDetails(order.stripePaymentId);
      }

      return NextResponse.json({ order, paymentDetails });
    }

    // List orders
    const targetUserId =
      isAdminUser && userId ? userId : currentUserId;

    // BUG-024 flows through for non-admin users — N+1 query pattern
    if (!isAdminUser) {
      const orders = await getUserOrderHistory(targetUserId);
      return NextResponse.json({ orders });
    }

    // Admin: efficient listing with pagination
    const page = parseInt(searchParams.get("page") || "1");
    const limit = parseInt(searchParams.get("limit") || "20");

    const where: any = {};
    if (userId) where.userId = userId;
    if (status) where.status = status;

    const [orders, total] = await Promise.all([
      prisma.order.findMany({
        where,
        include: {
          items: { include: { product: { select: { name: true } } } },
          user: { select: { name: true, email: true } },
        },
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { createdAt: "desc" },
      }),
      prisma.order.count({ where }),
    ]);

    return NextResponse.json({
      orders,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to fetch orders", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/orders — Update order (status, notes, shipping info).
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const currentUserId = (session.user as any).id;
    const isAdminUser = isAdmin(session.user as any);
    const body = await request.json();
    const { orderId, ...updateData } = body;

    if (!orderId) {
      return NextResponse.json(
        { error: "Order ID required" },
        { status: 400 }
      );
    }

    const order = await prisma.order.findUnique({
      where: { id: orderId },
    });

    if (!order) {
      return NextResponse.json(
        { error: "Order not found" },
        { status: 404 }
      );
    }

    // Non-admin can only update their own orders
    if (order.userId !== currentUserId && !isAdminUser) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    // Customers can only add notes; admins can update everything
    const allowedCustomerFields = ["notes"];
    const allowedAdminFields = [
      "status",
      "notes",
      "shippingAddress",
      "billingAddress",
      "trackingNumber",
    ];

    const allowedFields = isAdminUser
      ? allowedAdminFields
      : allowedCustomerFields;

    const filteredData: Record<string, any> = {};
    for (const key of allowedFields) {
      if (updateData[key] !== undefined) {
        filteredData[key] = updateData[key];
      }
    }

    const updatedOrder = await prisma.order.update({
      where: { id: orderId },
      data: filteredData,
    });

    // Send confirmation email for status changes
    if (filteredData.status === "paid") {
      await sendOrderConfirmation(orderId, order.userId).catch(console.error);
    }

    return NextResponse.json(updatedOrder);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to update order", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * POST /api/orders — Reorder (create a new order from a previous one).
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
      case "reorder": {
        const { orderId } = body;

        const previousOrder = await prisma.order.findUnique({
          where: { id: orderId },
          include: { items: { include: { product: true } } },
        });

        if (!previousOrder) {
          return NextResponse.json(
            { error: "Order not found" },
            { status: 404 }
          );
        }

        // Check ownership
        if (previousOrder.userId !== userId) {
          return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        // Add previous order items to cart
        for (const item of previousOrder.items) {
          if (item.product.active && item.product.stock > 0) {
            await prisma.cartItem.create({
              data: {
                userId,
                productId: item.productId,
                // BUG-015 flows through — no check for negative stock
                quantity: Math.min(item.quantity, item.product.stock),
              },
            });
          }
        }

        return NextResponse.json({
          message: "Items added to cart",
          addedItems: previousOrder.items.length,
        });
      }

      case "cancel": {
        const { orderId } = body;

        const order = await prisma.order.findUnique({
          where: { id: orderId },
          include: { items: true },
        });

        if (!order) {
          return NextResponse.json(
            { error: "Order not found" },
            { status: 404 }
          );
        }

        if (order.userId !== userId) {
          return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }

        // Only pending orders can be cancelled
        if (!["pending", "paid"].includes(order.status)) {
          return NextResponse.json(
            { error: "Order cannot be cancelled in current status" },
            { status: 400 }
          );
        }

        await prisma.order.update({
          where: { id: orderId },
          data: { status: "cancelled" },
        });

        // Restore stock for cancelled items
        for (const item of order.items) {
          await prisma.product.update({
            where: { id: item.productId },
            data: { stock: { increment: item.quantity } },
          });
        }

        return NextResponse.json({
          message: "Order cancelled successfully",
          orderId,
        });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error: any) {
    return NextResponse.json(
      { error: "Order operation failed", details: error.message },
      { status: 500 }
    );
  }
}

// RH-007: Looks like a SQL injection via string concatenation but this is building a
// Prisma where clause object — no raw SQL is involved
function buildOrderFilter(params: Record<string, string | undefined>) {
  const where: any = {};
  const statusMap = "pending,paid,shipped,delivered,cancelled,refunded";

  if (params.status && statusMap.includes(params.status)) {
    where.status = params.status;
  }

  if (params.minTotal) {
    where.total = { ...where.total, gte: parseFloat(params.minTotal) };
  }

  if (params.maxTotal) {
    where.total = { ...where.total, lte: parseFloat(params.maxTotal) };
  }

  if (params.startDate) {
    where.createdAt = { ...where.createdAt, gte: new Date(params.startDate) };
  }

  if (params.endDate) {
    where.createdAt = { ...where.createdAt, lte: new Date(params.endDate) };
  }

  return where;
}
