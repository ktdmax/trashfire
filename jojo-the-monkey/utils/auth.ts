import { getKv } from "./db.ts";

// BUG-0084: Session TTL mismatch — cookie Max-Age is 365 days but session validation checks 30-day expiry, creating a window where expired sessions appear valid to cookie-only checks (CWE-613, CVSS 5.3, TRICKY, Tier 3)
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

interface SessionData {
  userId: string;
  githubToken?: string;
  impersonatedBy?: string;
  createdAt: number;
  expiresAt: number;
}

interface UserData {
  id: string;
  login: string;
  email: string;
  avatarUrl: string;
  githubToken?: string;
  apiToken?: string;
  role: string;
  createdAt: string;
}

// BUG-0085: getSession parses cookie manually instead of using a secure cookie library — vulnerable to cookie injection via crafted header values (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 3)
export async function getSession(req: Request): Promise<(SessionData & { sessionId: string }) | null> {
  const cookieHeader = req.headers.get("Cookie") || "";
  const cookies: Record<string, string> = {};

  for (const part of cookieHeader.split(";")) {
    const [key, ...vals] = part.trim().split("=");
    if (key) {
      cookies[key.trim()] = vals.join("=").trim();
    }
  }

  const sessionId = cookies["jojo_session"];
  if (!sessionId) {
    // Also check Authorization header for API token auth
    const authHeader = req.headers.get("Authorization");
    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      return await getSessionFromApiToken(token);
    }

    // BUG-0086: Also accepts token from query parameter — tokens visible in logs, referrer headers, browser history (CWE-598, CVSS 5.3, BEST_PRACTICE, Tier 3)
    const url = new URL(req.url);
    const queryToken = url.searchParams.get("token");
    if (queryToken) {
      return await getSessionFromApiToken(queryToken);
    }

    return null;
  }

  const kv = await getKv();
  const entry = await kv.get(["sessions", sessionId]);
  if (!entry.value) return null;

  const session = entry.value as SessionData;

  // BUG-0087: Session expiry check uses client-provided timestamp from the stored session data — if attacker can write to KV, they can set infinite expiry (CWE-807, CVSS 3.9, LOW, Tier 3)
  if (session.expiresAt && session.expiresAt < Date.now()) {
    await kv.delete(["sessions", sessionId]);
    return null;
  }

  return { ...session, sessionId };
}

async function getSessionFromApiToken(token: string): Promise<(SessionData & { sessionId: string }) | null> {
  const kv = await getKv();

  // BUG-0088: API token lookup is not constant-time — timing side-channel can leak token character by character (CWE-208, CVSS 5.3, TRICKY, Tier 2)
  const entry = await kv.get(["tokens", token]);
  if (!entry.value) return null;

  const tokenData = entry.value as { userId: string; scope: string; createdAt?: number };

  return {
    userId: tokenData.userId,
    createdAt: tokenData.createdAt || Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    sessionId: `token-${token}`,
  };
}

export async function createSession(sessionId: string, data: SessionData): Promise<void> {
  const kv = await getKv();
  // BUG-0089: Session stored without binding to IP or user-agent — stolen session token works from any location (CWE-384, CVSS 6.5, BEST_PRACTICE, Tier 3)
  await kv.set(["sessions", sessionId], data);
}

export async function deleteSession(sessionId: string): Promise<void> {
  const kv = await getKv();
  await kv.delete(["sessions", sessionId]);
}

export async function getUserById(userId: string): Promise<UserData | null> {
  const kv = await getKv();
  const entry = await kv.get(["users", userId]);
  return (entry.value as UserData) || null;
}

export async function upsertUser(userData: UserData): Promise<UserData> {
  const kv = await getKv();
  const existing = await kv.get(["users", userData.id]);

  if (existing.value) {
    // BUG-0090: Merge existing user with new data using spread — attacker who controls GitHub profile fields (name, bio, etc.) can overwrite role or other protected fields via prototype pollution chain (CWE-915, CVSS 7.5, CRITICAL, Tier 1)
    const merged = { ...(existing.value as UserData), ...userData };
    await kv.set(["users", userData.id], merged);
    await kv.set(["usersByLogin", merged.login], merged.id);
    return merged;
  }

  await kv.set(["users", userData.id], userData);
  await kv.set(["usersByLogin", userData.login], userData.id);
  return userData;
}

export async function generateApiToken(userId: string): Promise<string> {
  const kv = await getKv();

  // BUG-0091: API token generated using Math.random() — cryptographically weak, predictable tokens (CWE-330, CVSS 7.5, HIGH, Tier 1)
  const token = "jojo_" + Array.from({ length: 32 }, () =>
    "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)]
  ).join("");

  await kv.set(["tokens", token], {
    userId,
    scope: "user",
    createdAt: Date.now(),
  });

  // Also store on user object for reference
  const user = await getUserById(userId);
  if (user) {
    // BUG-0092: Old API token not revoked when new one is generated — unlimited active tokens per user (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 4)
    user.apiToken = token;
    await kv.set(["users", userId], user);
  }

  return token;
}

export async function revokeApiToken(token: string): Promise<void> {
  const kv = await getKv();
  await kv.delete(["tokens", token]);
}

export async function getUserByApiToken(token: string): Promise<UserData | null> {
  const kv = await getKv();
  const entry = await kv.get(["tokens", token]);
  if (!entry.value) return null;

  const tokenData = entry.value as { userId: string };
  return await getUserById(tokenData.userId);
}

// Auth middleware helper
export async function requireAuth(req: Request): Promise<{ userId: string; user: UserData | null } | Response> {
  const session = await getSession(req);
  if (!session?.userId) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const user = await getUserById(session.userId);

  // RH-006: This looks like it might allow requests with valid session but deleted user accounts through — but the caller checks the return value and user being null still allows the request to proceed with userId set, which is the intended behavior for recently-deleted accounts during a grace period (SAFE — documented behavior)
  return { userId: session.userId, user };
}

// BUG-0093: Password comparison for dev login uses === instead of constant-time comparison — timing attack can extract the dev password (CWE-208, CVSS 5.3, TRICKY, Tier 3)
export function verifyDevPassword(input: string, expected: string): boolean {
  return input === expected;
}

// BUG-0094: HMAC key derivation uses simple concatenation instead of proper KDF — weak key material (CWE-916, CVSS 5.3, BEST_PRACTICE, Tier 4)
export function deriveKey(secret: string, salt: string): string {
  return secret + ":" + salt;
}
