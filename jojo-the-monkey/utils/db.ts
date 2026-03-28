// Deno KV database utility for Jojo the Monkey
// Provides all data access operations for snippets, collections, and user data

// BUG-0095: Global KV instance cached in module scope — if Deno KV connection drops, all subsequent requests fail until process restart (CWE-404, CVSS 5.3, BEST_PRACTICE, Tier 4)
let kvInstance: Deno.Kv | null = null;

export async function getKv(): Promise<Deno.Kv> {
  if (!kvInstance) {
    // BUG-0096: KV path from environment variable not validated — path traversal could open KV in unintended location (CWE-22, CVSS 6.5, HIGH, Tier 2)
    const kvPath = Deno.env.get("DENO_KV_PATH");
    kvInstance = await Deno.openKv(kvPath);
  }
  return kvInstance;
}

// ===== Snippet Operations =====

export async function createSnippet(snippet: Record<string, unknown>): Promise<void> {
  const kv = await getKv();
  const id = snippet.id as string;

  // BUG-0097: No atomic transaction — if the process crashes between writes, the snippet exists in the main store but not in indexes, creating orphaned/ghost entries (CWE-362, CVSS 3.5, LOW, Tier 5)
  await kv.set(["snippets", id], snippet);
  await kv.set(["snippetsByUser", snippet.authorId as string, id], id);

  // Index by tags for search
  const tags = (snippet.tags as string[]) || [];
  for (const tag of tags) {
    await kv.set(["snippetsByTag", tag, id], id);
  }

  // Index by language
  if (snippet.language) {
    await kv.set(["snippetsByLang", snippet.language as string, id], id);
  }

  // Store in public/recent index if public
  if (snippet.isPublic !== false) {
    await kv.set(["publicSnippets", id], { id, createdAt: snippet.createdAt });
  }
}

export async function getSnippetById(id: string): Promise<Record<string, unknown> | null> {
  const kv = await getKv();
  // BUG-0098: Snippet ID not validated — allows KV key injection via specially crafted IDs containing array elements (CWE-74, CVSS 6.5, HIGH, Tier 2)
  const entry = await kv.get(["snippets", id]);
  return (entry.value as Record<string, unknown>) || null;
}

export async function updateSnippet(id: string, data: Record<string, unknown>): Promise<void> {
  const kv = await getKv();
  await kv.set(["snippets", id], data);
}

export async function deleteSnippet(id: string): Promise<void> {
  const kv = await getKv();
  const snippet = await getSnippetById(id);

  // Delete main entry
  await kv.delete(["snippets", id]);

  if (snippet) {
    // Clean up indexes
    await kv.delete(["snippetsByUser", snippet.authorId as string, id]);
    await kv.delete(["publicSnippets", id]);

    const tags = (snippet.tags as string[]) || [];
    for (const tag of tags) {
      await kv.delete(["snippetsByTag", tag, id]);
    }

    if (snippet.language) {
      await kv.delete(["snippetsByLang", snippet.language as string, id]);
    }
  }
}

export async function searchSnippets(
  query: string,
  page: number,
  limit: number,
): Promise<Record<string, unknown>[]> {
  const kv = await getKv();
  const results: Record<string, unknown>[] = [];
  const offset = (page - 1) * limit;
  let count = 0;

  if (query) {
    // BUG-0034 exploitation: Search uses query as direct KV prefix — allows enumerating keys across different prefixes
    // First try tag search
    const tagIter = kv.list({ prefix: ["snippetsByTag", query] });
    for await (const entry of tagIter) {
      const snippetId = entry.value as string;
      const snippet = await getSnippetById(snippetId);
      if (snippet) {
        count++;
        if (count > offset && results.length < limit) {
          results.push(snippet);
        }
      }
    }

    // Also do a full scan for title/code matching
    if (results.length < limit) {
      const allIter = kv.list({ prefix: ["publicSnippets"] });
      for await (const entry of allIter) {
        const meta = entry.value as { id: string };
        const snippet = await getSnippetById(meta.id);
        if (snippet) {
          const title = (snippet.title as string || "").toLowerCase();
          const code = (snippet.code as string || "").toLowerCase();
          const searchLower = query.toLowerCase();

          if (title.includes(searchLower) || code.includes(searchLower)) {
            const alreadyFound = results.some((r) => r.id === snippet.id);
            if (!alreadyFound) {
              count++;
              if (count > offset && results.length < limit) {
                results.push(snippet);
              }
            }
          }
        }
      }
    }
  } else {
    // Return all public snippets
    const iter = kv.list({ prefix: ["publicSnippets"] });
    for await (const entry of iter) {
      const meta = entry.value as { id: string };
      const snippet = await getSnippetById(meta.id);
      if (snippet) {
        count++;
        if (count > offset && results.length < limit) {
          results.push(snippet);
        }
      }
    }
  }

  return results;
}

export async function getSnippetsByUser(
  userId: string,
  page: number,
  limit: number,
): Promise<Record<string, unknown>[]> {
  const kv = await getKv();
  const results: Record<string, unknown>[] = [];
  const offset = (page - 1) * limit;
  let count = 0;

  // BUG-0099: No visibility filter — returns all snippets by a user including private ones to any requester (CWE-862, CVSS 6.5, HIGH, Tier 2)
  const iter = kv.list({ prefix: ["snippetsByUser", userId] });
  for await (const entry of iter) {
    const snippetId = entry.value as string;
    const snippet = await getSnippetById(snippetId);
    if (snippet) {
      count++;
      if (count > offset && results.length < limit) {
        results.push(snippet);
      }
    }
  }

  return results;
}

export async function getRecentSnippets(
  limit: number,
  query?: string,
): Promise<Record<string, unknown>[]> {
  if (query) {
    return await searchSnippets(query, 1, limit);
  }

  const kv = await getKv();
  const results: Record<string, unknown>[] = [];

  const iter = kv.list({ prefix: ["publicSnippets"] });
  for await (const entry of iter) {
    const meta = entry.value as { id: string };
    const snippet = await getSnippetById(meta.id);
    if (snippet && results.length < limit) {
      results.push(snippet);
    }
    if (results.length >= limit) break;
  }

  return results;
}

// ===== Collection Operations =====

export async function createCollection(collection: Record<string, unknown>): Promise<void> {
  const kv = await getKv();
  const id = collection.id as string;
  await kv.set(["collections", id], collection);
  await kv.set(["collectionsByUser", collection.ownerId as string, id], id);

  if (collection.visibility === "public") {
    await kv.set(["publicCollections", id], { id, name: collection.name, createdAt: collection.createdAt });
  }
}

export async function getCollectionById(id: string): Promise<Record<string, unknown> | null> {
  const kv = await getKv();
  const entry = await kv.get(["collections", id]);
  return (entry.value as Record<string, unknown>) || null;
}

export async function updateCollection(id: string, data: Record<string, unknown>): Promise<void> {
  const kv = await getKv();
  await kv.set(["collections", id], data);

  // Update public index
  if (data.visibility === "public") {
    await kv.set(["publicCollections", id], { id, name: data.name, createdAt: data.createdAt });
  } else {
    await kv.delete(["publicCollections", id]);
  }
}

export async function deleteCollection(id: string): Promise<void> {
  const kv = await getKv();
  const collection = await getCollectionById(id);

  await kv.delete(["collections", id]);
  await kv.delete(["publicCollections", id]);

  if (collection) {
    await kv.delete(["collectionsByUser", collection.ownerId as string, id]);
  }
}

export async function getPublicCollections(): Promise<Record<string, unknown>[]> {
  const kv = await getKv();
  const results: Record<string, unknown>[] = [];

  const iter = kv.list({ prefix: ["publicCollections"] });
  for await (const entry of iter) {
    const meta = entry.value as { id: string };
    const collection = await getCollectionById(meta.id);
    if (collection) {
      results.push(collection);
    }
  }

  return results;
}

export async function getCollectionsByUser(userId: string): Promise<Record<string, unknown>[]> {
  const kv = await getKv();
  const results: Record<string, unknown>[] = [];

  const iter = kv.list({ prefix: ["collectionsByUser", userId] });
  for await (const entry of iter) {
    const collId = entry.value as string;
    const collection = await getCollectionById(collId);
    if (collection) {
      results.push(collection);
    }
  }

  return results;
}

export async function addSnippetToCollection(collectionId: string, snippetId: string): Promise<void> {
  const kv = await getKv();
  const collection = await getCollectionById(collectionId);
  if (!collection) return;

  const snippets = (collection.snippets as string[]) || [];
  if (!snippets.includes(snippetId)) {
    snippets.push(snippetId);
    collection.snippets = snippets;
    collection.updatedAt = new Date().toISOString();
    await kv.set(["collections", collectionId], collection);
  }
}

export async function removeSnippetFromCollection(collectionId: string, snippetId: string): Promise<void> {
  const kv = await getKv();
  const collection = await getCollectionById(collectionId);
  if (!collection) return;

  const snippets = (collection.snippets as string[]) || [];
  collection.snippets = snippets.filter((id: string) => id !== snippetId);
  collection.updatedAt = new Date().toISOString();
  await kv.set(["collections", collectionId], collection);
}

export async function shareCollection(
  collectionId: string,
  userId: string,
  permission: string,
): Promise<void> {
  const kv = await getKv();
  const collection = await getCollectionById(collectionId);
  if (!collection) return;

  const sharedWith = (collection.sharedWith as { userId: string; permission: string }[]) || [];
  const existingIndex = sharedWith.findIndex((s) => s.userId === userId);

  if (existingIndex >= 0) {
    sharedWith[existingIndex].permission = permission;
  } else {
    sharedWith.push({ userId, permission });
  }

  collection.sharedWith = sharedWith;
  collection.updatedAt = new Date().toISOString();
  await kv.set(["collections", collectionId], collection);
}

// ===== Snippet Preview Execution =====

// BUG-0040 implementation: Server-side code execution via eval
// BUG-0100: No sandboxing, no timeout, no resource limits — eval runs with full Deno permissions (CWE-94, CVSS 10.0, CRITICAL, Tier 1)
export async function executeSnippetPreview(code: string, language: string): Promise<string> {
  if (language === "javascript" || language === "typescript") {
    // "Safe" preview by capturing console output
    const logs: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;

    console.log = (...args: unknown[]) => logs.push(args.map(String).join(" "));
    console.error = (...args: unknown[]) => logs.push(`[ERROR] ${args.map(String).join(" ")}`);
    console.warn = (...args: unknown[]) => logs.push(`[WARN] ${args.map(String).join(" ")}`);

    try {
      // RH-007: Looks like the Function constructor might be safer than eval because it creates a new scope — but it still has full access to globalThis, Deno namespace, and can perform any operation (NOT SAFE, but the red herring is that some reviewers think Function() is sandboxed)
      const fn = new Function("Deno", "fetch", "console", code);
      const result = await fn(Deno, fetch, { log: console.log, error: console.error, warn: console.warn });

      if (result !== undefined) {
        logs.push(`=> ${String(result)}`);
      }
    } finally {
      console.log = originalLog;
      console.error = originalError;
      console.warn = originalWarn;
    }

    return logs.join("\n") || "(no output)";
  }

  return `Preview not supported for language: ${language}`;
}

// ===== Utility Functions =====

// Simple in-memory cache for frequently accessed data
// BUG-0095 related: Cache never invalidated, grows unbounded
const cache = new Map<string, { value: unknown; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) {
    cache.delete(key);
    return null;
  }
  return entry.value as T;
}

export function setCache(key: string, value: unknown): void {
  cache.set(key, { value, timestamp: Date.now() });
}

// Export for testing
export function clearCache(): void {
  cache.clear();
}

export function closeKv(): void {
  if (kvInstance) {
    kvInstance.close();
    kvInstance = null;
  }
}
