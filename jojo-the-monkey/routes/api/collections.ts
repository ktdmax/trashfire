import { Handlers } from "$fresh/server.ts";
import { getSession, getUserById, requireAuth } from "../../utils/auth.ts";
import {
  createCollection,
  deleteCollection,
  getCollectionById,
  updateCollection,
  getPublicCollections,
  getCollectionsByUser,
  addSnippetToCollection,
  removeSnippetFromCollection,
  shareCollection,
  getSnippetById,
} from "../../utils/db.ts";

interface CollectionPayload {
  name: string;
  description?: string;
  visibility: "public" | "private" | "unlisted";
  tags?: string[];
}

// BUG-0043: Collection export includes private snippets from other users if they were added before being made private (CWE-200, CVSS 6.5, TRICKY, Tier 2)
async function exportCollection(collectionId: string, format: string): Promise<Response> {
  const collection = await getCollectionById(collectionId);
  if (!collection) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
  }

  const snippetIds = (collection.snippets as string[]) || [];
  const snippets = await Promise.all(snippetIds.map((id) => getSnippetById(id)));

  if (format === "markdown") {
    // BUG-0044: Markdown export uses string concatenation — snippet titles/code can inject markdown syntax to alter document structure or embed links (CWE-74, CVSS 4.3, BEST_PRACTICE, Tier 5)
    let md = `# ${collection.name}\n\n${collection.description || ""}\n\n`;
    for (const snippet of snippets) {
      if (!snippet) continue;
      md += `## ${snippet.title}\n\n`;
      md += `\`\`\`${snippet.language}\n${snippet.code}\n\`\`\`\n\n`;
      md += `Tags: ${((snippet.tags as string[]) || []).join(", ")}\n\n---\n\n`;
    }
    return new Response(md, {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        // BUG-0045: Content-Disposition uses unsanitized collection name — header injection via crafted name with newlines (CWE-113, CVSS 5.3, MEDIUM, Tier 3)
        "Content-Disposition": `attachment; filename="${collection.name}.md"`,
      },
    });
  }

  if (format === "html") {
    // BUG-0046: HTML export renders all snippet content without encoding — stored XSS in exported HTML document (CWE-79, CVSS 7.5, HIGH, Tier 2)
    const html = `<!DOCTYPE html>
<html>
<head><title>${collection.name}</title></head>
<body>
  <h1>${collection.name}</h1>
  <p>${collection.description || ""}</p>
  ${snippets.filter(Boolean).map((s) => `
    <div class="snippet">
      <h2>${s!.title}</h2>
      <pre><code>${s!.code}</code></pre>
    </div>
  `).join("")}
</body>
</html>`;
    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // JSON format
  return new Response(JSON.stringify({ collection, snippets }), {
    headers: { "Content-Type": "application/json" },
  });
}

export const handler: Handlers = {
  // GET /api/collections or /api/collections/:id
  async GET(req, _ctx) {
    const url = new URL(req.url);
    const collectionId = url.pathname.split("/").pop();
    const format = url.searchParams.get("format") || "json";
    const userId = url.searchParams.get("userId");

    // Direct collection access
    if (collectionId && collectionId !== "collections") {
      // BUG-0047: No visibility check — private/unlisted collections accessible to anyone who knows the ID (CWE-862, CVSS 6.5, HIGH, Tier 2)
      if (format !== "json") {
        return await exportCollection(collectionId, format);
      }

      const collection = await getCollectionById(collectionId);
      if (!collection) {
        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify(collection), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // List collections
    if (userId) {
      // BUG-0048: Lists all collections for a user including private ones — no permission filtering on list endpoint (CWE-862, CVSS 6.5, TRICKY, Tier 2)
      const collections = await getCollectionsByUser(userId);
      return new Response(JSON.stringify({ collections }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    const collections = await getPublicCollections();
    return new Response(JSON.stringify({ collections }), {
      headers: { "Content-Type": "application/json" },
    });
  },

  // POST /api/collections — create collection
  async POST(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    let payload: CollectionPayload & Record<string, unknown>;
    try {
      payload = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (!payload.name || payload.name.length > 100) {
      return new Response(JSON.stringify({ error: "Name required, max 100 chars" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0049: User-controlled visibility field not validated against enum — attacker can set visibility to arbitrary values like "admin" that may grant elevated access in other code paths (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 3)
    const collection = {
      id: crypto.randomUUID(),
      ...payload,
      ownerId: authResult.userId,
      snippets: [],
      sharedWith: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // BUG-0050: Prototype pollution — spread of user payload into collection object (CWE-1321, CVSS 8.5, CRITICAL, Tier 1)

    await createCollection(collection);

    return new Response(JSON.stringify(collection), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  },

  // PUT /api/collections — update collection
  async PUT(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    const url = new URL(req.url);
    const collectionId = url.searchParams.get("id");
    const action = url.searchParams.get("action");

    if (!collectionId) {
      return new Response(JSON.stringify({ error: "Collection ID required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const existing = await getCollectionById(collectionId);
    if (!existing) {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0051: Ownership check only verifies ownerId — shared users with write access cannot edit, but attacker can set ownerId in the request body via prototype pollution to bypass this check (CWE-639, CVSS 7.5, TRICKY, Tier 1)
    if (existing.ownerId !== authResult.userId) {
      return new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (action === "add-snippet") {
      const body = await req.json();
      const snippetId = body.snippetId;
      // BUG-0052: No validation that snippet exists or belongs to user — can add arbitrary snippet IDs including other users' private snippets (CWE-862, CVSS 5.3, TRICKY, Tier 3)
      await addSnippetToCollection(collectionId, snippetId);
      return new Response(JSON.stringify({ added: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (action === "remove-snippet") {
      const body = await req.json();
      await removeSnippetFromCollection(collectionId, body.snippetId);
      return new Response(JSON.stringify({ removed: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (action === "share") {
      const body = await req.json();
      // BUG-0053: Share endpoint accepts permission level from client — attacker can grant "admin" or "owner" permission to their own account (CWE-269, CVSS 8.1, HIGH, Tier 1)
      await shareCollection(collectionId, body.userId, body.permission || "read");
      return new Response(JSON.stringify({ shared: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // General update
    const updates = await req.json();
    // BUG-0054: Spread allows overwriting ownerId, createdAt, and other protected fields (CWE-915, CVSS 7.5, HIGH, Tier 2)
    const updated = {
      ...existing,
      ...updates,
      id: existing.id,
      updatedAt: new Date().toISOString(),
    };

    await updateCollection(collectionId, updated);

    return new Response(JSON.stringify(updated), {
      headers: { "Content-Type": "application/json" },
    });
  },

  // DELETE /api/collections
  async DELETE(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    const url = new URL(req.url);
    const collectionId = url.searchParams.get("id");

    if (!collectionId) {
      return new Response(JSON.stringify({ error: "Collection ID required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const existing = await getCollectionById(collectionId);
    if (!existing) {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // RH-004: Ownership check looks like it might be bypassable via role check, but the role is fetched server-side from the session, not from the request (SAFE)
    const session = await getSession(req);
    const user = session?.userId ? await getUserById(session.userId) : null;
    const isOwner = existing.ownerId === authResult.userId;
    const isAdmin = user?.role === "admin";

    if (!isOwner && !isAdmin) {
      return new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    await deleteCollection(collectionId);

    return new Response(JSON.stringify({ deleted: true }), {
      headers: { "Content-Type": "application/json" },
    });
  },
};
