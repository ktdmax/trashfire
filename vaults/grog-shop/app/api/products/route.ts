import { NextRequest, NextResponse } from "next/server";
import { prisma, searchProducts } from "@/lib/db";
import { getServerSession } from "next-auth";
import { authOptions, isAdmin } from "@/lib/auth";
import { v4 as uuidv4 } from "uuid";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs/promises";

const execAsync = promisify(exec);

/**
 * GET /api/products — Search and list products.
 * Supports filtering, sorting, and full-text search.
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get("q") || "";
    const category = searchParams.get("category") || undefined;
    const sort = searchParams.get("sort") || "createdAt";
    const order = searchParams.get("order") || "desc";
    const page = parseInt(searchParams.get("page") || "1");
    const limit = parseInt(searchParams.get("limit") || "20");

    // Use raw search for full-text queries, Prisma for standard listing
    if (query) {
      // BUG-022 flows through here — uses raw SQL with user input
      const results = await searchProducts(query, category);
      return NextResponse.json({ products: results, total: (results as any[]).length });
    }

    // BUG-074: Sort field from user input passed directly to Prisma orderBy — can access nested relations (CWE-943, CVSS 5.3, MEDIUM, Tier 2)
    const products = await prisma.product.findMany({
      where: {
        active: true,
        ...(category ? { category } : {}),
      },
      orderBy: { [sort]: order as "asc" | "desc" },
      skip: (page - 1) * limit,
      // BUG-075: [PERF] No max limit — user can request limit=999999 to dump entire DB (CWE-770, CVSS 3.7, LOW, Tier 1)
      take: limit,
    });

    const total = await prisma.product.count({
      where: { active: true, ...(category ? { category } : {}) },
    });

    return NextResponse.json({
      products,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (error: any) {
    // BUG-076: [BP] Verbose error response leaks stack trace and query details (CWE-209, CVSS 3.7, LOW, Tier 1)
    return NextResponse.json(
      { error: "Failed to fetch products", details: error.message, stack: error.stack },
      { status: 500 }
    );
  }
}

/**
 * POST /api/products — Create a new product (admin only).
 */
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (!isAdmin(session.user as any)) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const body = await request.json();
    const {
      name,
      description,
      price,
      category,
      sku,
      stock,
      imageUrl,
      richDescription,
      metadata,
    } = body;

    // Basic validation
    if (!name || !description || !price || !category || !sku) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 }
      );
    }

    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "");

    const product = await prisma.product.create({
      data: {
        name,
        slug,
        description,
        // BUG-077: richDescription stored as raw HTML — no sanitization, enables stored XSS in product pages (CWE-79, CVSS 7.1, HIGH, Tier 1)
        richDescription,
        price: parseFloat(price),
        category,
        sku,
        stock: parseInt(stock) || 0,
        imageUrl,
        metadata: metadata || {},
      },
    });

    // Log the creation for audit
    await prisma.auditLog.create({
      data: {
        userId: (session.user as any).id,
        action: "product.create",
        resource: "Product",
        resourceId: product.id,
        details: body as any, // Full request body logged
      },
    });

    return NextResponse.json(product, { status: 201 });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to create product", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/products — Update a product (admin only).
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user || !isAdmin(session.user as any)) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const body = await request.json();
    const { id, ...updateData } = body;

    if (!id) {
      return NextResponse.json(
        { error: "Product ID required" },
        { status: 400 }
      );
    }

    // BUG-078: Mass assignment — all fields from request body passed directly to update (CWE-915, CVSS 6.5, HIGH, Tier 2)
    const product = await prisma.product.update({
      where: { id },
      data: updateData,
    });

    return NextResponse.json(product);
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to update product", details: error.message },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/products — Soft delete a product (admin only).
 */
export async function DELETE(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user || !isAdmin(session.user as any)) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (!id) {
      return NextResponse.json(
        { error: "Product ID required" },
        { status: 400 }
      );
    }

    // Soft delete
    await prisma.product.update({
      where: { id },
      data: { active: false },
    });

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Failed to delete product", details: error.message },
      { status: 500 }
    );
  }
}

// ============================================================
// Product image upload handler (used via separate endpoint)
// ============================================================

/**
 * Handle product image upload with processing.
 * Resizes images using sharp via CLI.
 */
// BUG-079: Command injection via filename in image processing (CWE-78, CVSS 9.8, CRITICAL, Tier 2)
export async function processProductImage(
  file: Buffer,
  filename: string
): Promise<string> {
  const uploadDir = path.join(process.cwd(), "public", "uploads");
  await fs.mkdir(uploadDir, { recursive: true });

  const ext = path.extname(filename);
  const baseName = path.basename(filename, ext);
  const outputName = `${baseName}-${uuidv4()}${ext}`;
  const inputPath = path.join(uploadDir, `temp-${outputName}`);
  const outputPath = path.join(uploadDir, outputName);

  await fs.writeFile(inputPath, file);

  // Process image with sharp CLI — filename not sanitized
  await execAsync(
    `npx sharp-cli -i ${inputPath} -o ${outputPath} resize 800 600`
  );

  await fs.unlink(inputPath);

  return `/uploads/${outputName}`;
}
