import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import {
  getCart,
  addToCart,
  updateCartItemQuantity,
  removeFromCart,
  clearCart,
  applyDiscount,
  mergeGuestCart,
} from "@/lib/cart";
import { prisma } from "@/lib/db";

/**
 * GET /api/cart — Get the current user's cart.
 */
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = (session.user as any).id;
    const cart = await getCart(userId);

    return NextResponse.json(cart);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to fetch cart", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * POST /api/cart — Add item to cart or perform cart actions.
 * Actions: add, merge, apply-discount, clear
 */
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = (session.user as any).id;
    const body = await request.json();
    const { action = "add" } = body;

    switch (action) {
      case "add": {
        const { productId, quantity = 1 } = body;

        if (!productId) {
          return NextResponse.json(
            { error: "Product ID required" },
            { status: 400 }
          );
        }

        const item = await addToCart(userId, productId, quantity);
        const cart = await getCart(userId);
        return NextResponse.json({ item, cart });
      }

      case "merge": {
        // Merge guest cart items after login
        const { items } = body;

        if (!Array.isArray(items)) {
          return NextResponse.json(
            { error: "Items array required" },
            { status: 400 }
          );
        }

        // BUG-065 flows through here — mergeGuestCart doesn't validate product IDs
        const cart = await mergeGuestCart(userId, items);
        return NextResponse.json(cart);
      }

      case "apply-discount": {
        const { code } = body;

        if (!code) {
          return NextResponse.json(
            { error: "Discount code required" },
            { status: 400 }
          );
        }

        const result = await applyDiscount(userId, code);
        return NextResponse.json(result);
      }

      case "clear": {
        await clearCart(userId);
        return NextResponse.json({ success: true, items: [], subtotal: 0 });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error: any) {
    return NextResponse.json(
      { error: "Cart operation failed", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/cart — Update cart item quantity.
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = (session.user as any).id;
    const body = await request.json();
    const { cartItemId, quantity } = body;

    if (!cartItemId || quantity === undefined) {
      return NextResponse.json(
        { error: "Cart item ID and quantity required" },
        { status: 400 }
      );
    }

    // BUG-060 flows through — updateCartItemQuantity doesn't verify ownership
    const item = await updateCartItemQuantity(cartItemId, quantity);
    const cart = await getCart(userId);

    return NextResponse.json({ item, cart });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to update cart item", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/cart — Remove item from cart.
 */
export async function DELETE(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const cartItemId = searchParams.get("id");

    if (!cartItemId) {
      return NextResponse.json(
        { error: "Cart item ID required" },
        { status: 400 }
      );
    }

    // BUG-061 flows through — removeFromCart doesn't verify ownership
    await removeFromCart(cartItemId);
    const userId = (session.user as any).id;
    const cart = await getCart(userId);

    return NextResponse.json(cart);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to remove cart item", details: error.message },
      { status: 500 }
    );
  }
}
