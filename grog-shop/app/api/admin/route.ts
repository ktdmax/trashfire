import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions, isAdmin, verifyToken } from "@/lib/auth";
import { prisma, getSalesReport, findUsers } from "@/lib/db";
import { createRefund, getPaymentDetails } from "@/lib/stripe";
import { sendBulkEmail, sendShippingNotification } from "@/lib/email";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs/promises";

const execAsync = promisify(exec);

// BUG-084: Admin auth check uses OR logic — either session OR API token grants access (CWE-863, CVSS 8.1, CRITICAL, Tier 3)
async function requireAdmin(request: NextRequest) {
  // Check session first
  const session = await getServerSession(authOptions);
  if (session?.user && isAdmin(session.user as any)) {
    return { user: session.user, method: "session" };
  }

  // Fall back to API token from header
  const authHeader = request.headers.get("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    const decoded = verifyToken(token);
    // BUG-085: API token admin check only verifies token validity, not admin role (CWE-862, CVSS 9.1, CRITICAL, Tier 3)
    if (decoded) {
      return { user: decoded, method: "token" };
    }
  }

  return null;
}

/**
 * GET /api/admin — Admin dashboard data.
 * Returns stats, recent orders, and system info.
 */
export async function GET(request: NextRequest) {
  const admin = await requireAdmin(request);
  if (!admin) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { searchParams } = new URL(request.url);
  const action = searchParams.get("action") || "dashboard";

  try {
    switch (action) {
      case "dashboard": {
        const [userCount, orderCount, productCount, revenue] =
          await Promise.all([
            prisma.user.count(),
            prisma.order.count(),
            prisma.product.count({ where: { active: true } }),
            prisma.order.aggregate({
              _sum: { total: true },
              where: { status: "paid" },
            }),
          ]);

        const recentOrders = await prisma.order.findMany({
          take: 10,
          orderBy: { createdAt: "desc" },
          include: { user: { select: { name: true, email: true } } },
        });

        return NextResponse.json({
          stats: {
            users: userCount,
            orders: orderCount,
            products: productCount,
            revenue: revenue._sum.total || 0,
          },
          recentOrders,
        });
      }

      case "sales-report": {
        const startDate = searchParams.get("startDate") || "2024-01-01";
        const endDate = searchParams.get("endDate") || new Date().toISOString();
        const groupBy = searchParams.get("groupBy") || "day";

        // BUG-023 flows through here — SQL injection in report query
        const report = await getSalesReport(startDate, endDate, groupBy);
        return NextResponse.json({ report });
      }

      case "users": {
        const search = searchParams.get("search") || "";
        const sortField = searchParams.get("sortField") || "createdAt";
        const sortOrder = searchParams.get("sortOrder") || "desc";

        // BUG-025 flows through here — SQL injection in user search
        const users = await findUsers(search, sortField, sortOrder);
        return NextResponse.json({ users });
      }

      case "audit-log": {
        const logs = await prisma.auditLog.findMany({
          take: 100,
          orderBy: { createdAt: "desc" },
          // BUG-086: Audit log returns full details including passwords and tokens (CWE-532, CVSS 6.5, MEDIUM, Tier 1)
        });
        return NextResponse.json({ logs });
      }

      case "export": {
        const format = searchParams.get("format") || "json";
        const resource = searchParams.get("resource") || "orders";

        // BUG-087: Path traversal via resource parameter in export (CWE-22, CVSS 7.5, HIGH, Tier 2)
        const exportPath = path.join(
          process.cwd(),
          "exports",
          `${resource}-${Date.now()}.${format}`
        );

        let data: any;
        if (resource === "orders") {
          data = await prisma.order.findMany({ include: { items: true, user: true } });
        } else if (resource === "users") {
          // BUG-088: User export includes passwordHash and resetToken fields (CWE-200, CVSS 7.5, HIGH, Tier 2)
          data = await prisma.user.findMany();
        } else if (resource === "products") {
          data = await prisma.product.findMany();
        } else {
          return NextResponse.json({ error: "Unknown resource" }, { status: 400 });
        }

        await fs.mkdir(path.dirname(exportPath), { recursive: true });
        await fs.writeFile(exportPath, JSON.stringify(data, null, 2));

        return NextResponse.json({ path: exportPath, count: data.length });
      }

      // BUG-089: System info endpoint exposes environment variables and system details (CWE-200, CVSS 6.5, CRITICAL, Tier 1)
      case "system-info": {
        return NextResponse.json({
          env: process.env,
          nodeVersion: process.version,
          platform: process.platform,
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cwd: process.cwd(),
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
      { error: "Admin operation failed", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * POST /api/admin — Admin actions (orders, users, emails, system).
 */
export async function POST(request: NextRequest) {
  const admin = await requireAdmin(request);
  if (!admin) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = await request.json();
  const { action } = body;

  try {
    switch (action) {
      case "update-order-status": {
        const { orderId, status, trackingNumber, carrier } = body;

        const order = await prisma.order.update({
          where: { id: orderId },
          data: { status },
        });

        if (status === "shipped" && trackingNumber) {
          // BUG-071 flows through here — carrier parameter in tracking URL
          await sendShippingNotification(orderId, trackingNumber, carrier);
        }

        return NextResponse.json({ order });
      }

      case "refund": {
        const { orderId, amount, reason } = body;
        // BUG-054 flows through here — refund amount from client
        const refund = await createRefund(orderId, amount, reason);
        return NextResponse.json({ refund });
      }

      case "update-user-role": {
        const { userId, role } = body;
        // BUG-090: No validation on role value — can set arbitrary role strings (CWE-20, CVSS 8.1, HIGH, Tier 2)
        const user = await prisma.user.update({
          where: { id: userId },
          data: { role },
        });
        return NextResponse.json({ user });
      }

      case "send-email": {
        const { subject, htmlContent, filter } = body;
        // BUG-091: Admin can send arbitrary HTML email to all users — email injection / phishing vector (CWE-74, CVSS 6.5, MEDIUM, Tier 2)
        const result = await sendBulkEmail(subject, htmlContent, filter);
        return NextResponse.json(result);
      }

      case "run-maintenance": {
        const { command } = body;
        // BUG-092: Remote code execution — admin can execute arbitrary shell commands (CWE-78, CVSS 10.0, CRITICAL, Tier 1)
        const { stdout, stderr } = await execAsync(command, {
          timeout: 30000,
          cwd: process.cwd(),
        });

        return NextResponse.json({
          stdout,
          stderr,
          exitCode: 0,
        });
      }

      case "import-products": {
        const { data, format } = body;

        // BUG-093: Deserialization of untrusted JSON — prototype pollution via __proto__ in product data (CWE-1321, CVSS 7.5, TRICKY, Tier 3)
        const products = typeof data === "string" ? JSON.parse(data) : data;

        const results = [];
        for (const product of products) {
          // Merge imported data without sanitization
          const merged = Object.assign({}, product);
          const created = await prisma.product.create({
            data: {
              name: merged.name,
              slug: merged.slug || merged.name.toLowerCase().replace(/\s+/g, "-"),
              description: merged.description || "",
              price: merged.price,
              category: merged.category || "uncategorized",
              sku: merged.sku || `IMPORT-${Date.now()}`,
              stock: merged.stock || 0,
              imageUrl: merged.imageUrl,
              richDescription: merged.richDescription,
              metadata: merged.metadata,
            },
          });
          results.push(created);
        }

        return NextResponse.json({
          imported: results.length,
          products: results,
        });
      }

      // RH-005: Looks like eval() on user input but the template is a hardcoded constant —
      // only string substitution is performed, no code execution
      case "generate-report-template": {
        const templates: Record<string, string> = {
          daily: "Daily Sales Report - {{date}}",
          weekly: "Weekly Summary Report - Week {{week}}",
          monthly: "Monthly Revenue Report - {{month}} {{year}}",
        };
        const { templateName, variables } = body;
        const template = templates[templateName] || templates.daily;
        let result = template;
        for (const [key, value] of Object.entries(variables || {})) {
          result = result.replace(`{{${key}}}`, String(value));
        }
        return NextResponse.json({ report: result });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error: any) {
    return NextResponse.json(
      { error: "Admin action failed", details: error.message, stack: error.stack },
      { status: 500 }
    );
  }
}
