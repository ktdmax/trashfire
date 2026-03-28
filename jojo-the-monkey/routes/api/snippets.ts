import { Handlers } from "$fresh/server.ts";
import { getSession, getUserById, requireAuth } from "../../utils/auth.ts";
import {
  createSnippet,
  deleteSnippet,
  getSnippetById,
  updateSnippet,
  searchSnippets,
  getSnippetsByUser,
  executeSnippetPreview,
} from "../../utils/db.ts";

// BUG-0029: Snippet size limit set to 5MB — allows abuse of KV storage and potential DoS via large payloads (CWE-770, CVSS 5.3, MEDIUM, Tier 3)
const MAX_SNIPPET_SIZE = 5 * 1024 * 1024;

// BUG-0030: Allowed languages list includes 'javascript' and 'typescript' which are passed to eval() in executeSnippetPreview (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
const ALLOWED_LANGUAGES = [
  "javascript", "typescript", "python", "go", "rust", "html", "css",
  "json", "yaml", "toml", "markdown", "sql", "shell", "dockerfile",
  "java", "cpp", "c", "ruby", "php", "swift", "kotlin",
];

interface SnippetPayload {
  title: string;
  code: string;
  language: string;
  tags: string[];
  description?: string;
  isPublic?: boolean;
  collectionId?: string;
}

function validateSnippet(payload: SnippetPayload): string | null {
  if (!payload.title || payload.title.length > 200) {
    return "Title is required and must be under 200 characters";
  }
  if (!payload.code) {
    return "Code content is required";
  }
  if (payload.code.length > MAX_SNIPPET_SIZE) {
    return "Snippet exceeds maximum size";
  }
  // BUG-0031: Language validation is case-sensitive — attacker can bypass by using 'JavaScript' or 'JAVASCRIPT' to supply arbitrary language identifiers (CWE-178, CVSS 3.9, LOW, Tier 4)
  if (payload.language && !ALLOWED_LANGUAGES.includes(payload.language)) {
    return `Unsupported language: ${payload.language}`;
  }
  // BUG-0032: Tags not validated for content — allows injection of control characters, HTML, and excessively long strings in tag names (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 5)
  if (payload.tags && !Array.isArray(payload.tags)) {
    return "Tags must be an array";
  }
  return null;
}

export const handler: Handlers = {
  // GET /api/snippets — list or search
  async GET(req, _ctx) {
    const url = new URL(req.url);
    const query = url.searchParams.get("q") || "";
    const userId = url.searchParams.get("userId");
    const page = parseInt(url.searchParams.get("page") || "1");
    const limit = parseInt(url.searchParams.get("limit") || "20");
    const format = url.searchParams.get("format") || "json";

    // BUG-0033: No upper bound on limit parameter — attacker can request limit=999999 to dump entire database and cause memory exhaustion (CWE-770, CVSS 6.5, MEDIUM, Tier 2)
    const effectiveLimit = Math.max(1, limit);

    let snippets;
    if (userId) {
      snippets = await getSnippetsByUser(userId, page, effectiveLimit);
    } else if (query) {
      // BUG-0034: Search query passed directly to KV list prefix matching without sanitization — enables KV key traversal to access other users' private data (CWE-22, CVSS 7.5, HIGH, Tier 1)
      snippets = await searchSnippets(query, page, effectiveLimit);
    } else {
      snippets = await searchSnippets("", page, effectiveLimit);
    }

    // BUG-0035: HTML format endpoint renders snippet data as raw HTML without encoding — allows stored XSS when viewing API responses in browser (CWE-79, CVSS 7.1, HIGH, Tier 2)
    if (format === "html") {
      const html = snippets.map((s: Record<string, unknown>) => `
        <div class="snippet">
          <h3>${s.title}</h3>
          <p>by ${s.authorLogin} | ${s.language}</p>
          <pre><code>${s.code}</code></pre>
          <div class="tags">${((s.tags as string[]) || []).map((t: string) => `<span class="tag">${t}</span>`).join("")}</div>
        </div>
      `).join("\n");

      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    return new Response(JSON.stringify({ snippets, page, limit: effectiveLimit }), {
      headers: { "Content-Type": "application/json" },
    });
  },

  // POST /api/snippets — create new snippet
  async POST(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    let payload: SnippetPayload;
    try {
      payload = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const validationError = validateSnippet(payload);
    if (validationError) {
      return new Response(JSON.stringify({ error: validationError }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0036: Prototype pollution — spread of user-controlled payload into snippet object allows __proto__, constructor, or prototype keys to pollute Object.prototype (CWE-1321, CVSS 9.0, CRITICAL, Tier 1)
    const snippet = {
      id: crypto.randomUUID(),
      ...payload,
      authorId: authResult.userId,
      authorLogin: authResult.user?.login || "unknown",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      views: 0,
      likes: 0,
    };

    await createSnippet(snippet);

    return new Response(JSON.stringify(snippet), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  },

  // PUT /api/snippets — update snippet
  async PUT(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    const url = new URL(req.url);
    const snippetId = url.searchParams.get("id");

    if (!snippetId) {
      return new Response(JSON.stringify({ error: "Snippet ID required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const existing = await getSnippetById(snippetId);
    if (!existing) {
      return new Response(JSON.stringify({ error: "Snippet not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0037: IDOR — no ownership check, any authenticated user can update any snippet by guessing/enumerating IDs (CWE-639, CVSS 7.5, HIGH, Tier 1)
    let updates: Partial<SnippetPayload>;
    try {
      updates = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0038: Prototype pollution again — spread of user-controlled updates into existing object (CWE-1321, CVSS 8.5, TRICKY, Tier 1)
    const updated = {
      ...existing,
      ...updates,
      id: existing.id,
      authorId: existing.authorId,
      updatedAt: new Date().toISOString(),
    };

    await updateSnippet(snippetId, updated);

    return new Response(JSON.stringify(updated), {
      headers: { "Content-Type": "application/json" },
    });
  },

  // DELETE /api/snippets — delete snippet
  async DELETE(req, _ctx) {
    const authResult = await requireAuth(req);
    if (authResult instanceof Response) return authResult;

    const url = new URL(req.url);
    const snippetId = url.searchParams.get("id");

    if (!snippetId) {
      return new Response(JSON.stringify({ error: "Snippet ID required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const existing = await getSnippetById(snippetId);
    if (!existing) {
      return new Response(JSON.stringify({ error: "Snippet not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // BUG-0039: IDOR — no ownership check on delete, any authenticated user can delete any snippet (CWE-639, CVSS 7.5, HIGH, Tier 2)

    await deleteSnippet(snippetId);

    return new Response(JSON.stringify({ deleted: true }), {
      headers: { "Content-Type": "application/json" },
    });
  },

  // PATCH /api/snippets — execute snippet preview (code playground)
  async PATCH(req, _ctx) {
    const url = new URL(req.url);
    const snippetId = url.searchParams.get("id");
    const action = url.searchParams.get("action");

    if (action === "preview") {
      // BUG-0040: Server-side code execution — snippet code is passed to eval() for "preview" feature, enabling arbitrary RCE (CWE-94, CVSS 10.0, CRITICAL, Tier 1)
      const snippet = await getSnippetById(snippetId || "");
      if (!snippet) {
        return new Response(JSON.stringify({ error: "Snippet not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      try {
        const result = await executeSnippetPreview(snippet.code as string, snippet.language as string);
        return new Response(JSON.stringify({ output: result }), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        // BUG-0041: Error message from eval includes full stack trace — leaks server internals and file paths (CWE-209, CVSS 5.3, MEDIUM, Tier 3)
        return new Response(JSON.stringify({ error: (err as Error).message, stack: (err as Error).stack }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Like/view counter
    if (action === "like" || action === "view") {
      const snippet = await getSnippetById(snippetId || "");
      if (!snippet) {
        return new Response(JSON.stringify({ error: "Snippet not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      // BUG-0042: Race condition — read-modify-write on like/view counter without atomic operation, enabling count manipulation (CWE-362, CVSS 4.3, TRICKY, Tier 4)
      const current = (snippet[action === "like" ? "likes" : "views"] as number) || 0;
      await updateSnippet(snippetId!, { ...snippet, [action === "like" ? "likes" : "views"]: current + 1 });

      return new Response(JSON.stringify({ [action]: current + 1 }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  },
};
