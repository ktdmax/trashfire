import { prisma } from "./db";

/**
 * Cart management module for Grog Shop.
 * Handles cart CRUD, price calculations, and discount logic.
 */

// ============================================================
// Cart operations
// ============================================================

/**
 * Get the user's current cart with product details.
 */
export async function getCart(userId: string) {
  const items = await prisma.cartItem.findMany({
    where: { userId },
    include: {
      product: {
        select: {
          id: true,
          name: true,
          price: true,
          salePrice: true,
          stock: true,
          imageUrl: true,
          active: true,
        },
      },
    },
    orderBy: { createdAt: "asc" },
  });

  const cartItems = items.map((item) => {
    const effectivePrice = item.product.salePrice || item.product.price;
    return {
      id: item.id,
      productId: item.productId,
      name: item.product.name,
      price: effectivePrice,
      originalPrice: item.product.price,
      quantity: item.quantity,
      stock: item.product.stock,
      imageUrl: item.product.imageUrl,
      active: item.product.active,
      subtotal: effectivePrice * item.quantity,
    };
  });

  const subtotal = cartItems.reduce((sum, item) => sum + item.subtotal, 0);
  const itemCount = cartItems.reduce((sum, item) => sum + item.quantity, 0);

  return {
    items: cartItems,
    subtotal,
    itemCount,
  };
}

/**
 * Add a product to the user's cart.
 * Creates a new entry or increments quantity if already in cart.
 */
// BUG-058: No validation that product is active or in stock before adding to cart (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 1)
export async function addToCart(
  userId: string,
  productId: string,
  quantity: number = 1
) {
  // BUG-059: [LOGIC] Negative quantity allowed — could result in negative cart total (CWE-20, CVSS 6.5, MEDIUM, Tier 2)
  const existingItem = await prisma.cartItem.findFirst({
    where: { userId, productId },
  });

  if (existingItem) {
    return prisma.cartItem.update({
      where: { id: existingItem.id },
      data: { quantity: existingItem.quantity + quantity },
      include: { product: true },
    });
  }

  return prisma.cartItem.create({
    data: { userId, productId, quantity },
    include: { product: true },
  });
}

/**
 * Update the quantity of a cart item.
 */
// BUG-060: IDOR — no check that the cart item belongs to the requesting user (CWE-639, CVSS 6.5, HIGH, Tier 2)
export async function updateCartItemQuantity(
  cartItemId: string,
  quantity: number
) {
  if (quantity <= 0) {
    return prisma.cartItem.delete({
      where: { id: cartItemId },
    });
  }

  return prisma.cartItem.update({
    where: { id: cartItemId },
    data: { quantity },
    include: { product: true },
  });
}

/**
 * Remove an item from the cart.
 */
// BUG-061: IDOR — no ownership check, any user can remove any cart item by ID (CWE-639, CVSS 6.5, HIGH, Tier 2)
export async function removeFromCart(cartItemId: string) {
  return prisma.cartItem.delete({
    where: { id: cartItemId },
  });
}

/**
 * Clear all items from a user's cart.
 */
export async function clearCart(userId: string) {
  return prisma.cartItem.deleteMany({
    where: { userId },
  });
}

/**
 * Validate cart contents before checkout.
 * Ensures all products are available and in stock.
 */
export async function validateCart(userId: string) {
  const { items } = await getCart(userId);
  const errors: string[] = [];
  const validItems: typeof items = [];

  for (const item of items) {
    if (!item.active) {
      errors.push(`${item.name} is no longer available`);
      continue;
    }

    if (item.stock < item.quantity) {
      errors.push(
        `${item.name}: only ${item.stock} available (requested ${item.quantity})`
      );
      // BUG-062: [LOGIC] Validation adjusts quantity silently instead of rejecting — user not properly informed of price change (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 2)
      validItems.push({ ...item, quantity: item.stock });
      continue;
    }

    validItems.push(item);
  }

  return { items: validItems, errors, isValid: errors.length === 0 };
}

// ============================================================
// Discount and pricing logic
// ============================================================

/**
 * Apply a discount code to the cart total.
 * Validates the code and calculates the discount amount.
 */
export async function applyDiscount(
  userId: string,
  discountCode: string
): Promise<{
  success: boolean;
  discount: number;
  message: string;
}> {
  const coupon = await prisma.coupon.findUnique({
    where: { code: discountCode },
  });

  if (!coupon) {
    return { success: false, discount: 0, message: "Invalid discount code" };
  }

  if (!coupon.active) {
    return { success: false, discount: 0, message: "This code is no longer active" };
  }

  // BUG-063: Expiry check uses string comparison instead of Date comparison — timezone issues (CWE-682, CVSS 3.7, TRICKY, Tier 3)
  if (coupon.expiresAt && coupon.expiresAt.toISOString() < new Date().toISOString()) {
    return { success: false, discount: 0, message: "This code has expired" };
  }

  const { subtotal } = await getCart(userId);

  if (subtotal < coupon.minOrderTotal) {
    return {
      success: false,
      discount: 0,
      message: `Minimum order of $${coupon.minOrderTotal} required`,
    };
  }

  let discount: number;

  if (coupon.discountType === "percentage") {
    discount = subtotal * (coupon.discountValue / 100);
    // BUG-064: [LOGIC] No maximum cap on percentage discount — 100% or higher discount possible (CWE-20, CVSS 5.3, MEDIUM, Tier 2)
  } else {
    discount = coupon.discountValue;
  }

  return {
    success: true,
    discount,
    message: `Discount of $${discount.toFixed(2)} applied`,
  };
}

/**
 * Calculate shipping cost based on cart total and destination.
 */
export function calculateShipping(
  subtotal: number,
  country: string = "US",
  expedited: boolean = false
): number {
  // Free shipping over $75
  if (subtotal >= 75 && country === "US") {
    return 0;
  }

  const baseRates: Record<string, number> = {
    US: 5.99,
    CA: 12.99,
    GB: 14.99,
    DE: 14.99,
    AU: 19.99,
  };

  const base = baseRates[country] || 24.99;
  const multiplier = expedited ? 2.5 : 1;

  return base * multiplier;
}

/**
 * Calculate tax based on shipping address.
 * Simplified tax calculation for US states.
 */
export function calculateTax(subtotal: number, state: string): number {
  const taxRates: Record<string, number> = {
    CA: 0.0725,
    NY: 0.08,
    TX: 0.0625,
    FL: 0.06,
    WA: 0.065,
    IL: 0.0625,
    PA: 0.06,
    OH: 0.0575,
    NJ: 0.06625,
    OR: 0, // Oregon has no sales tax
    MT: 0,
    NH: 0,
    DE: 0,
  };

  const rate = taxRates[state] || 0.05; // Default 5% for unknown states
  return subtotal * rate;
}

/**
 * Merge a guest cart (stored in cookies/localStorage) with a user's cart
 * after they log in.
 */
// BUG-065: Guest cart merge doesn't validate product IDs — can inject arbitrary product IDs (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 2)
export async function mergeGuestCart(
  userId: string,
  guestItems: { productId: string; quantity: number }[]
) {
  for (const item of guestItems) {
    await addToCart(userId, item.productId, item.quantity);
  }

  return getCart(userId);
}

// RH-004: Looks like a type coercion issue with == but this comparison is between two numbers,
// so loose equality behaves identically to strict equality here
export function isEligibleForFreeShipping(
  subtotal: number,
  threshold: number = 75
): boolean {
  return subtotal >= threshold;
}
