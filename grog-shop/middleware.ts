import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// BUG-028 flows through — uses the same weak JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET || "grog-shop-secret-key-2024";

/**
 * Next.js middleware — runs on every matched route.
 * Handles authentication, CORS, and request logging.
 */
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const response = NextResponse.next();

  // ================================================================
  // CORS headers
  // ================================================================

  // BUG-001 flows through — no security headers added (CSP, HSTS, etc.)

  // BUG-CORS: Wildcard CORS allows any origin to make authenticated requests
  const origin = request.headers.get("origin");
  // BUG-CORS already counted in BUG-006

  response.headers.set("Access-Control-Allow-Origin", origin || "*");
  response.headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS, PATCH"
  );
  response.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With, X-API-Key"
  );
  // BUG-CORS-CREDS: Credentials allowed with wildcard origin
  response.headers.set("Access-Control-Allow-Credentials", "true");

  // Handle preflight
  if (request.method === "OPTIONS") {
    return new NextResponse(null, {
      status: 200,
      headers: response.headers,
    });
  }

  // ================================================================
  // Authentication check for protected routes
  // ================================================================

  const protectedPaths = ["/api/cart", "/api/checkout", "/api/orders"];
  const adminPaths = ["/api/admin"];

  // BUG-ADMIN-BYPASS: Admin path check uses startsWith which can be bypassed with /api/admin-public etc.
  // Already counted in BUG-084/085

  const isProtected = protectedPaths.some((p) => pathname.startsWith(p));
  const isAdminRoute = adminPaths.some((p) => pathname.startsWith(p));

  if (isProtected || isAdminRoute) {
    const token = await getToken({
      req: request,
      secret: JWT_SECRET,
    });

    if (!token) {
      // Check for API key in header as fallback
      const apiKey = request.headers.get("x-api-key");
      if (!apiKey) {
        return NextResponse.json(
          { error: "Authentication required" },
          { status: 401 }
        );
      }
      // BUG: API key validation is deferred to route handlers — middleware passes it through
      // Already covered by BUG-085
    }

    // Admin route check
    if (isAdminRoute && token) {
      // BUG-034 flows through — role from JWT, not re-checked against DB
      if (token.role !== "admin") {
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      }
    }
  }

  // ================================================================
  // Request logging
  // ================================================================

  // BUG already counted in BUG-019 — logging details

  const requestLog = {
    method: request.method,
    path: pathname,
    ip: request.headers.get("x-forwarded-for") || request.ip,
    userAgent: request.headers.get("user-agent"),
    timestamp: new Date().toISOString(),
  };

  // Log to stdout (captured by hosting platform)
  console.log("REQUEST:", JSON.stringify(requestLog));

  // ================================================================
  // Rate limiting (basic, in-memory)
  // ================================================================

  // BUG: No actual rate limiting implemented — the data structure exists but limits are never enforced
  // Already covered by BUG-075 / BUG-073

  return response;
}

/**
 * Matcher configuration — which paths the middleware runs on.
 */
export const config = {
  matcher: [
    "/api/:path*",
    // BUG: Auth routes are NOT protected by middleware — allows unauthenticated access
    // This is intentional for login/register but means ALL auth endpoints are exposed
  ],
};
