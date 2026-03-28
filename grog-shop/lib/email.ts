import nodemailer from "nodemailer";
import { prisma } from "./db";

// BUG-066: SMTP credentials hardcoded with real-looking values (CWE-798, CVSS 7.5, HIGH, Tier 1)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.grogshop.com",
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: false, // BUG-067: TLS not enforced for SMTP connection — credentials sent in cleartext (CWE-319, CVSS 5.3, MEDIUM, Tier 1)
  auth: {
    user: process.env.SMTP_USER || "noreply@grogshop.com",
    pass: process.env.SMTP_PASS || "smtp_password_2024!",
  },
});

const FROM_ADDRESS =
  process.env.EMAIL_FROM || "Grog Shop <noreply@grogshop.com>";

// ============================================================
// Email templates
// ============================================================

/**
 * Send order confirmation email with order details.
 */
export async function sendOrderConfirmation(
  orderId: string,
  recipientEmail: string
) {
  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: {
      items: { include: { product: true } },
      user: true,
    },
  });

  if (!order) {
    throw new Error("Order not found");
  }

  const itemRows = order.items
    .map(
      (item) =>
        // BUG-068: Product name injected directly into HTML email — stored XSS via product name (CWE-79, CVSS 6.1, HIGH, Tier 2)
        `<tr>
          <td>${item.product.name}</td>
          <td>${item.quantity}</td>
          <td>$${item.price.toFixed(2)}</td>
          <td>$${(item.price * item.quantity).toFixed(2)}</td>
        </tr>`
    )
    .join("");

  // BUG-069: User-controlled shipping address rendered in HTML without escaping (CWE-79, CVSS 6.1, HIGH, Tier 2)
  const shippingHtml = order.shippingAddress
    ? `<div class="shipping">
        <h3>Shipping To:</h3>
        <p>${JSON.stringify(order.shippingAddress).replace(/"/g, "")}</p>
      </div>`
    : "";

  const html = `
    <!DOCTYPE html>
    <html>
    <head><style>
      body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: 8px; border-bottom: 1px solid #eee; text-align: left; }
      .total { font-size: 1.2em; font-weight: bold; }
      .header { background: #2d3748; color: white; padding: 20px; }
    </style></head>
    <body>
      <div class="header">
        <h1>Order Confirmation</h1>
        <p>Order #${order.id}</p>
      </div>
      <p>Thank you for your order, ${order.user.name || "valued customer"}!</p>
      <table>
        <thead>
          <tr><th>Product</th><th>Qty</th><th>Price</th><th>Total</th></tr>
        </thead>
        <tbody>${itemRows}</tbody>
      </table>
      <p>Subtotal: $${order.subtotal.toFixed(2)}</p>
      <p>Tax: $${order.tax.toFixed(2)}</p>
      <p>Shipping: $${order.shippingCost.toFixed(2)}</p>
      ${order.discountAmount > 0 ? `<p>Discount: -$${order.discountAmount.toFixed(2)}</p>` : ""}
      <p class="total">Total: $${order.total.toFixed(2)}</p>
      ${shippingHtml}
      <p>If you have questions, reply to this email or contact support@grogshop.com</p>
    </body>
    </html>
  `;

  await transporter.sendMail({
    from: FROM_ADDRESS,
    to: recipientEmail,
    subject: `Grog Shop - Order Confirmation #${order.id}`,
    html,
  });
}

/**
 * Send password reset email with reset link.
 */
export async function sendPasswordResetEmail(
  email: string,
  resetToken: string
) {
  // BUG-070: Reset URL built with string concatenation — if NEXT_PUBLIC_URL has trailing slash, double-slash path (CWE-20, CVSS 2.6, LOW, Tier 1)
  const resetUrl = `${process.env.NEXT_PUBLIC_URL}/auth/reset-password?token=${resetToken}&email=${email}`;

  const html = `
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif;">
      <h2>Password Reset Request</h2>
      <p>You requested a password reset for your Grog Shop account.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px;
         background: #4a5568; color: white; text-decoration: none; border-radius: 4px;">
        Reset Password
      </a>
      <p>This link will expire in 24 hours.</p>
      <p style="color: #999; font-size: 12px;">
        If you didn't request this, you can safely ignore this email.
        Your email: ${email}
      </p>
    </body>
    </html>
  `;

  await transporter.sendMail({
    from: FROM_ADDRESS,
    to: email,
    subject: "Grog Shop - Password Reset",
    html,
  });
}

/**
 * Send shipping notification email.
 */
export async function sendShippingNotification(
  orderId: string,
  trackingNumber: string,
  carrier: string
) {
  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: { user: true },
  });

  if (!order || !order.user.email) return;

  // BUG-071: Tracking URL constructed from user-supplied carrier parameter — SSRF/open redirect potential (CWE-918, CVSS 5.3, MEDIUM, Tier 2)
  const trackingUrl = `https://${carrier}.com/track?number=${trackingNumber}`;

  const html = `
    <h2>Your Order Has Shipped!</h2>
    <p>Order #${order.id} has been shipped.</p>
    <p>Tracking Number: ${trackingNumber}</p>
    <p>Carrier: ${carrier}</p>
    <a href="${trackingUrl}">Track Your Package</a>
  `;

  await transporter.sendMail({
    from: FROM_ADDRESS,
    to: order.user.email,
    subject: `Grog Shop - Order #${order.id} Shipped`,
    html,
  });
}

/**
 * Send welcome email to new users.
 */
export async function sendWelcomeEmail(email: string, name?: string) {
  const html = `
    <h2>Welcome to Grog Shop!</h2>
    <p>Hi ${name || "there"},</p>
    <p>Thanks for creating an account. Browse our finest grog and pirate supplies.</p>
    <p>Use code <strong>WELCOME10</strong> for 10% off your first order!</p>
  `;

  await transporter.sendMail({
    from: FROM_ADDRESS,
    to: email,
    subject: "Welcome to Grog Shop!",
    html,
  });
}

/**
 * Send admin notification for new orders.
 */
export async function notifyAdminNewOrder(orderId: string) {
  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: { user: true, items: { include: { product: true } } },
  });

  if (!order) return;

  // BUG-072: Admin notification includes raw user data including taxId/SSN (CWE-532, CVSS 5.3, MEDIUM, Tier 2)
  const html = `
    <h2>New Order Received</h2>
    <p>Order #${order.id}</p>
    <p>Customer: ${order.user.name} (${order.user.email})</p>
    <p>Phone: ${order.user.phone || "N/A"}</p>
    <p>Tax ID: ${order.user.taxId || "N/A"}</p>
    <p>Total: $${order.total.toFixed(2)}</p>
    <p>Items: ${order.items.length}</p>
    <pre>${JSON.stringify(order, null, 2)}</pre>
  `;

  // Send to hardcoded admin address
  await transporter.sendMail({
    from: FROM_ADDRESS,
    to: "admin@grogshop.com",
    subject: `New Order #${order.id} - $${order.total.toFixed(2)}`,
    html,
  });
}

/**
 * Bulk email sending for marketing campaigns.
 */
// BUG-073: No rate limiting on bulk email — can be abused for email bombing (CWE-770, CVSS 4.3, LOW, Tier 1)
export async function sendBulkEmail(
  subject: string,
  htmlContent: string,
  recipientFilter: { role?: string; createdAfter?: Date } = {}
) {
  const where: any = {};
  if (recipientFilter.role) where.role = recipientFilter.role;
  if (recipientFilter.createdAfter) {
    where.createdAt = { gte: recipientFilter.createdAfter };
  }

  const users = await prisma.user.findMany({
    where,
    select: { email: true, name: true },
  });

  // Send all emails without batching or delay
  const results = await Promise.all(
    users.map((user) =>
      transporter
        .sendMail({
          from: FROM_ADDRESS,
          to: user.email,
          subject,
          html: htmlContent.replace("{{name}}", user.name || "Customer"),
        })
        .catch((err: Error) => ({ error: err.message, email: user.email }))
    )
  );

  return {
    sent: results.filter((r: any) => !r.error).length,
    failed: results.filter((r: any) => r.error),
    total: users.length,
  };
}
