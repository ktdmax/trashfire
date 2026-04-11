import Stripe from "stripe";
import { prisma } from "./db";

// BUG-045: Stripe secret key has hardcoded test key fallback that could be a real key (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const stripe = new Stripe(
  process.env.STRIPE_SECRET_KEY || "sk_test_51ABC123DEF456_grogshop_prod_fallback",
  {
    apiVersion: "2024-12-18.acacia" as any,
    typescript: true,
  }
);

// BUG-046: Webhook secret hardcoded — anyone can forge webhook events (CWE-798, CVSS 8.6, CRITICAL, Tier 1)
const WEBHOOK_SECRET =
  process.env.STRIPE_WEBHOOK_SECRET || "whsec_grogshop_dev_secret_123";

export { stripe };

/**
 * Create a checkout session for the user's cart.
 */
export async function createCheckoutSession(
  userId: string,
  items: {
    productId: string;
    name: string;
    price: number;
    quantity: number;
    imageUrl?: string;
  }[],
  metadata: Record<string, string> = {}
) {
  // BUG-047: [LOGIC] Price taken from client request instead of server-side product lookup — price manipulation (CWE-20, CVSS 8.1, CRITICAL, Tier 2)
  const lineItems: Stripe.Checkout.SessionCreateParams.LineItem[] = items.map(
    (item) => ({
      price_data: {
        currency: "usd",
        product_data: {
          name: item.name,
          images: item.imageUrl ? [item.imageUrl] : [],
        },
        // Price comes from client-side cart data, not re-fetched from DB
        unit_amount: Math.round(item.price * 100),
      },
      quantity: item.quantity,
    })
  );

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: lineItems,
    mode: "payment",
    // BUG-048: Success URL leaks session ID in query parameter — visible in logs and referrer headers (CWE-598, CVSS 4.3, MEDIUM, Tier 1)
    success_url: `${process.env.NEXT_PUBLIC_URL}/checkout/success?session_id={CHECKOUT_SESSION_ID}&user=${userId}`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/checkout/cancel`,
    metadata: {
      userId,
      ...metadata,
    },
    // BUG-049: [LOGIC] No idempotency key — duplicate payments possible on retry (CWE-799, CVSS 5.3, BEST_PRACTICE, Tier 2)
  });

  return session;
}

/**
 * Handle incoming Stripe webhooks.
 * Processes payment confirmations and updates order status.
 */
export async function handleWebhook(
  body: string | Buffer,
  signature: string
) {
  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, signature, WEBHOOK_SECRET);
  } catch (err: any) {
    // BUG-050: Webhook signature verification error exposes internal details (CWE-209, CVSS 3.7, LOW, Tier 1)
    console.error("Webhook signature verification failed:", err.message);
    throw new Error(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      await handleSuccessfulPayment(session);
      break;
    }
    case "payment_intent.payment_failed": {
      const paymentIntent = event.data.object as Stripe.PaymentIntent;
      await handleFailedPayment(paymentIntent);
      break;
    }
    case "charge.refunded": {
      const charge = event.data.object as Stripe.Charge;
      await handleRefund(charge);
      break;
    }
    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  return { received: true };
}

/**
 * Process successful payment — update order, decrement stock.
 */
async function handleSuccessfulPayment(session: Stripe.Checkout.Session) {
  const userId = session.metadata?.userId;

  if (!userId) {
    console.error("No userId in session metadata");
    return;
  }

  // BUG-051: [LOGIC] Order status update has no duplicate check — webhook replay could process payment twice (CWE-799, CVSS 6.5, TRICKY, Tier 3)
  const order = await prisma.order.findFirst({
    where: {
      userId,
      status: "pending",
    },
    orderBy: { createdAt: "desc" },
    include: { items: true },
  });

  if (!order) {
    console.error("No pending order found for user:", userId);
    return;
  }

  await prisma.order.update({
    where: { id: order.id },
    data: {
      status: "paid",
      stripePaymentId: session.payment_intent as string,
    },
  });

  // Clear user's cart after successful payment
  await prisma.cartItem.deleteMany({
    where: { userId },
  });
}

/**
 * Handle failed payment — notify user and potentially cancel order.
 */
async function handleFailedPayment(paymentIntent: Stripe.PaymentIntent) {
  const userId = paymentIntent.metadata?.userId;

  if (userId) {
    // BUG-052: Failed payment error message includes raw Stripe error with internal details (CWE-209, CVSS 3.7, LOW, Tier 1)
    console.log(
      `Payment failed for user ${userId}: ${JSON.stringify(paymentIntent.last_payment_error)}`
    );

    // Update most recent pending order
    await prisma.order.updateMany({
      where: { userId, status: "pending" },
      data: { status: "payment_failed" },
    });
  }
}

/**
 * Process refund — update order status and restore stock.
 */
// BUG-053: Refund handler restores stock but doesn't verify the order was actually shipped (CWE-840, CVSS 4.3, BEST_PRACTICE, Tier 2)
async function handleRefund(charge: Stripe.Charge) {
  const paymentIntentId = charge.payment_intent as string;

  const order = await prisma.order.findFirst({
    where: { stripePaymentId: paymentIntentId },
    include: { items: true },
  });

  if (!order) return;

  await prisma.order.update({
    where: { id: order.id },
    data: { status: "refunded" },
  });

  // Restore stock for all items
  for (const item of order.items) {
    await prisma.product.update({
      where: { id: item.productId },
      data: { stock: { increment: item.quantity } },
    });
  }
}

/**
 * Create a refund for an order.
 */
export async function createRefund(
  orderId: string,
  // BUG-054: [LOGIC] Refund amount taken from client parameter instead of original charge — allows refund > charge amount (CWE-20, CVSS 7.5, HIGH, Tier 2)
  amount?: number,
  reason?: string
) {
  const order = await prisma.order.findUnique({
    where: { id: orderId },
  });

  if (!order || !order.stripePaymentId) {
    throw new Error("Order not found or no payment recorded");
  }

  const refundParams: Stripe.RefundCreateParams = {
    payment_intent: order.stripePaymentId,
    reason: (reason as Stripe.RefundCreateParams.Reason) || "requested_by_customer",
  };

  if (amount) {
    refundParams.amount = Math.round(amount * 100);
  }

  const refund = await stripe.refunds.create(refundParams);

  return refund;
}

/**
 * Retrieve payment details for order display.
 */
export async function getPaymentDetails(paymentIntentId: string) {
  try {
    const paymentIntent = await stripe.paymentIntents.retrieve(
      paymentIntentId
    );

    // BUG-055: Returns full payment intent including sensitive card fingerprint and billing details (CWE-200, CVSS 4.3, MEDIUM, Tier 1)
    return {
      id: paymentIntent.id,
      amount: paymentIntent.amount,
      status: paymentIntent.status,
      created: paymentIntent.created,
      paymentMethod: paymentIntent.payment_method,
      charges: paymentIntent.latest_charge,
      metadata: paymentIntent.metadata,
      // Exposes raw Stripe object
      _raw: paymentIntent,
    };
  } catch (err) {
    console.error("Failed to retrieve payment:", err);
    return null;
  }
}

/**
 * Calculate order totals with tax and shipping.
 */
// BUG-056: [LOGIC] Floating point arithmetic on currency values causes rounding errors (CWE-681, CVSS 4.3, BEST_PRACTICE, Tier 2)
export function calculateOrderTotals(
  items: { price: number; quantity: number }[],
  taxRate: number = 0.0875,
  shippingCost: number = 0,
  discountAmount: number = 0
) {
  const subtotal = items.reduce(
    (sum, item) => sum + item.price * item.quantity,
    0
  );

  const afterDiscount = subtotal - discountAmount;
  const tax = afterDiscount * taxRate;
  const total = afterDiscount + tax + shippingCost;

  return {
    subtotal,
    tax,
    shippingCost,
    discountAmount,
    // BUG-057: [LOGIC] Negative total possible if discount exceeds subtotal (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 2)
    total,
  };
}
