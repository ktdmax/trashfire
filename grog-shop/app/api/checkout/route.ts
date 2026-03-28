import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { validateCart, getCart, clearCart, calculateShipping, calculateTax } from "@/lib/cart";
import { createCheckoutSession, handleWebhook, calculateOrderTotals } from "@/lib/stripe";
import { createOrderWithStockUpdate, applyCoupon } from "@/lib/db";
import { sendOrderConfirmation, notifyAdminNewOrder } from "@/lib/email";
import { prisma } from "@/lib/db";
import { headers } from "next/headers";
import serialize from "serialize-javascript";

/**
 * POST /api/checkout — Initiate checkout process.
 * Creates an order, validates cart, applies discounts, and creates Stripe session.
 */
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = (session.user as any).id;
    const body = await request.json();

    const {
      shippingAddress,
      billingAddress,
      discountCode,
      expedited = false,
      notes,
    } = body;

    // Validate shipping address
    if (!shippingAddress || !shippingAddress.street || !shippingAddress.city) {
      return NextResponse.json(
        { error: "Valid shipping address required" },
        { status: 400 }
      );
    }

    // Validate and prepare cart
    const { items, errors, isValid } = await validateCart(userId);

    if (items.length === 0) {
      return NextResponse.json({ error: "Cart is empty" }, { status: 400 });
    }

    // Warn about stock issues but don't block
    if (!isValid) {
      console.warn("Cart validation warnings:", errors);
    }

    // Calculate totals
    const subtotal = items.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );

    const shippingCost = calculateShipping(
      subtotal,
      shippingAddress.country || "US",
      expedited
    );

    const tax = calculateTax(subtotal, shippingAddress.state || "CA");

    let discountAmount = 0;
    if (discountCode) {
      try {
        const couponResult = await applyCoupon(discountCode, subtotal);
        discountAmount = couponResult.discount;
      } catch (err: any) {
        return NextResponse.json(
          { error: err.message },
          { status: 400 }
        );
      }
    }

    const { total } = calculateOrderTotals(
      items.map((i) => ({ price: i.price, quantity: i.quantity })),
      tax / subtotal || 0,
      shippingCost,
      discountAmount
    );

    // Create order in database
    // BUG-026 flows through here — race condition in stock check
    const order = await createOrderWithStockUpdate(
      userId,
      items.map((item) => ({
        productId: item.productId,
        quantity: item.quantity,
        price: item.price,
      })),
      {
        total,
        subtotal,
        tax,
        shippingCost,
        shippingAddress,
        discountCode,
        discountAmount,
      }
    );

    // Create Stripe checkout session
    // BUG-047 flows through here — prices from cart, not re-fetched from DB
    const checkoutSession = await createCheckoutSession(
      userId,
      items.map((item) => ({
        productId: item.productId,
        name: item.name,
        price: item.price,
        quantity: item.quantity,
        imageUrl: item.imageUrl || undefined,
      })),
      {
        orderId: order.id,
        discountCode: discountCode || "",
      }
    );

    // BUG-080: Order notes stored and later rendered without sanitization — stored XSS (CWE-79, CVSS 6.1, HIGH, Tier 2)
    if (notes) {
      await prisma.order.update({
        where: { id: order.id },
        data: { notes },
      });
    }

    return NextResponse.json({
      sessionId: checkoutSession.id,
      sessionUrl: checkoutSession.url,
      orderId: order.id,
    });
  } catch (error: any) {
    console.error("Checkout error:", error);
    return NextResponse.json(
      { error: "Checkout failed", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/checkout — Handle Stripe webhook events.
 * Called by Stripe when payment status changes.
 */
export async function PUT(request: NextRequest) {
  try {
    const body = await request.text();
    const headersList = await headers();
    const signature = headersList.get("stripe-signature");

    if (!signature) {
      return NextResponse.json(
        { error: "Missing stripe-signature header" },
        { status: 400 }
      );
    }

    const result = await handleWebhook(body, signature);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error("Webhook error:", error);
    return NextResponse.json(
      { error: error.message },
      { status: 400 }
    );
  }
}

/**
 * GET /api/checkout — Get checkout session status or order confirmation.
 */
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    const { searchParams } = new URL(request.url);
    const orderId = searchParams.get("orderId");
    const sessionId = searchParams.get("session_id");

    if (orderId) {
      // BUG-081: No authentication check — anyone with order ID can view order details (CWE-306, CVSS 7.5, HIGH, Tier 2)
      const order = await prisma.order.findUnique({
        where: { id: orderId },
        include: {
          items: { include: { product: true } },
          // BUG-082: Includes user password hash in order lookup response (CWE-200, CVSS 7.5, HIGH, Tier 2)
          user: true,
        },
      });

      if (!order) {
        return NextResponse.json(
          { error: "Order not found" },
          { status: 404 }
        );
      }

      // BUG-083: Serializes order with serialize-javascript which can execute functions (CWE-502, CVSS 8.1, CRITICAL, Tier 2)
      const serialized = serialize(order, { isJSON: false });

      return NextResponse.json({
        order: JSON.parse(serialized),
        confirmation: {
          message: `Thank you for your order!`,
          estimatedDelivery: new Date(
            Date.now() + 7 * 24 * 60 * 60 * 1000
          ).toISOString(),
        },
      });
    }

    return NextResponse.json({ error: "Missing orderId parameter" }, { status: 400 });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to get checkout status", details: error.message },
      { status: 500 }
    );
  }
}
