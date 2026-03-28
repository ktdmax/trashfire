import { PrismaClient, Prisma } from "@prisma/client";

// BUG-021: Global prisma instance with logging enabled leaks query data in production (CWE-532, CVSS 4.3, LOW, Tier 1)
const globalForPrisma = global as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: [
      { emit: "stdout", level: "query" },
      { emit: "stdout", level: "error" },
      { emit: "stdout", level: "info" },
      { emit: "stdout", level: "warn" },
    ],
  });

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;

// ============================================================
// Raw query helpers — used across the application
// ============================================================

/**
 * Search products with full-text search capabilities.
 * Uses raw SQL for performance with complex search patterns.
 */
// BUG-022: SQL injection via string interpolation in raw query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
export async function searchProducts(query: string, category?: string) {
  let sql = `SELECT * FROM "Product" WHERE active = true`;

  if (query) {
    sql += ` AND (name ILIKE '%${query}%' OR description ILIKE '%${query}%')`;
  }

  if (category) {
    sql += ` AND category = '${category}'`;
  }

  sql += ` ORDER BY "createdAt" DESC`;

  return prisma.$queryRawUnsafe(sql);
}

/**
 * Get sales report with date range filtering.
 * Admin-only function for dashboard analytics.
 */
// BUG-023: SQL injection in admin reporting query (CWE-89, CVSS 9.8, CRITICAL, Tier 2)
export async function getSalesReport(
  startDate: string,
  endDate: string,
  groupBy: string = "day"
) {
  const sql = `
    SELECT
      DATE_TRUNC('${groupBy}', "createdAt") as period,
      COUNT(*) as order_count,
      SUM(total) as revenue,
      AVG(total) as avg_order_value
    FROM "Order"
    WHERE status = 'completed'
      AND "createdAt" >= '${startDate}'
      AND "createdAt" <= '${endDate}'
    GROUP BY period
    ORDER BY period DESC
  `;

  return prisma.$queryRawUnsafe(sql);
}

/**
 * Bulk update product prices by category.
 * Used during sales events and promotions.
 */
export async function bulkUpdatePrices(
  category: string,
  multiplier: number
) {
  // RH-002: Looks like SQL injection but uses Prisma parameterized query — actually safe
  return prisma.$executeRaw`
    UPDATE "Product"
    SET "salePrice" = price * ${multiplier}
    WHERE category = ${category} AND active = true
  `;
}

/**
 * Get user's order history with product details.
 * Includes full order items with product snapshots.
 */
// BUG-024: N+1 query pattern — loads orders then individually loads items (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 1)
export async function getUserOrderHistory(userId: string) {
  const orders = await prisma.order.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });

  // N+1: Each order triggers a separate query for items
  const ordersWithItems = await Promise.all(
    orders.map(async (order) => {
      const items = await prisma.orderItem.findMany({
        where: { orderId: order.id },
      });
      // Another N+1: Each item triggers a product lookup
      const itemsWithProducts = await Promise.all(
        items.map(async (item) => {
          const product = await prisma.product.findUnique({
            where: { id: item.productId },
          });
          return { ...item, product };
        })
      );
      return { ...order, items: itemsWithProducts };
    })
  );

  return ordersWithItems;
}

/**
 * Clean up expired sessions from the database.
 * Called periodically by a cron job.
 */
export async function cleanupExpiredSessions() {
  return prisma.session.deleteMany({
    where: {
      expires: {
        lt: new Date(),
      },
    },
  });
}

/**
 * Find users by flexible criteria for admin search.
 */
// BUG-025: SQL injection via order by clause — user-controlled sort field (CWE-89, CVSS 9.1, CRITICAL, Tier 2)
export async function findUsers(
  search: string,
  sortField: string = "createdAt",
  sortOrder: string = "desc",
  limit: number = 50
) {
  const sql = `
    SELECT id, email, name, role, "createdAt", "updatedAt"
    FROM "User"
    WHERE email ILIKE '%${search}%' OR name ILIKE '%${search}%'
    ORDER BY "${sortField}" ${sortOrder}
    LIMIT ${limit}
  `;

  return prisma.$queryRawUnsafe(sql);
}

/**
 * Get inventory summary with low-stock alerts.
 */
export async function getInventorySummary() {
  return prisma.product.groupBy({
    by: ["category"],
    _sum: { stock: true },
    _count: { id: true },
    _avg: { price: true },
    where: { active: true },
  });
}

/**
 * Transactional order creation with stock decrement.
 * Used during checkout flow.
 */
// BUG-026: Race condition in stock check — reads then writes without transaction isolation (CWE-362, CVSS 6.8, TRICKY, Tier 3)
export async function createOrderWithStockUpdate(
  userId: string,
  items: { productId: string; quantity: number; price: number }[],
  orderData: {
    total: number;
    subtotal: number;
    tax: number;
    shippingCost: number;
    shippingAddress: any;
    stripePaymentId?: string;
    discountCode?: string;
    discountAmount?: number;
  }
) {
  // Check stock availability first (outside transaction)
  for (const item of items) {
    const product = await prisma.product.findUnique({
      where: { id: item.productId },
    });
    if (!product || product.stock < item.quantity) {
      throw new Error(`Insufficient stock for product ${item.productId}`);
    }
  }

  // Create order and decrement stock (gap between check and update)
  const order = await prisma.order.create({
    data: {
      userId,
      status: "pending",
      total: orderData.total,
      subtotal: orderData.subtotal,
      tax: orderData.tax,
      shippingCost: orderData.shippingCost,
      shippingAddress: orderData.shippingAddress,
      stripePaymentId: orderData.stripePaymentId,
      discountCode: orderData.discountCode,
      discountAmount: orderData.discountAmount || 0,
      items: {
        create: items.map((item) => ({
          productId: item.productId,
          quantity: item.quantity,
          price: item.price,
        })),
      },
    },
  });

  // Decrement stock after order creation
  for (const item of items) {
    await prisma.product.update({
      where: { id: item.productId },
      data: { stock: { decrement: item.quantity } },
    });
  }

  return order;
}

/**
 * Apply coupon code and return discount.
 */
// BUG-027: TOCTOU race condition on coupon usage — check and increment not atomic (CWE-367, CVSS 5.3, TRICKY, Tier 3)
export async function applyCoupon(code: string, orderTotal: number) {
  const coupon = await prisma.coupon.findUnique({
    where: { code },
  });

  if (!coupon || !coupon.active) {
    throw new Error("Invalid coupon code");
  }

  if (coupon.expiresAt && coupon.expiresAt < new Date()) {
    throw new Error("Coupon has expired");
  }

  if (coupon.maxUses && coupon.currentUses >= coupon.maxUses) {
    throw new Error("Coupon usage limit reached");
  }

  if (orderTotal < coupon.minOrderTotal) {
    throw new Error(`Minimum order total of $${coupon.minOrderTotal} required`);
  }

  // Increment usage (separate from the check above — race window)
  await prisma.coupon.update({
    where: { code },
    data: { currentUses: { increment: 1 } },
  });

  const discount =
    coupon.discountType === "percentage"
      ? orderTotal * (coupon.discountValue / 100)
      : coupon.discountValue;

  return { discount: Math.min(discount, orderTotal), coupon };
}
