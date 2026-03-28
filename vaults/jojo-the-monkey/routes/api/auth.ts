import { Handlers } from "$fresh/server.ts";
import {
  createSession,
  deleteSession,
  getSession,
  getUserById,
  upsertUser,
  generateApiToken,
  revokeApiToken,
  getUserByApiToken,
} from "../../utils/auth.ts";
import { getKv } from "../../utils/db.ts";

// BUG-0055: GitHub OAuth client secret stored in source code as fallback — exposed in version control (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const GITHUB_CLIENT_ID = Deno.env.get("GITHUB_CLIENT_ID") || "Iv1.abc123monkey456";
const GITHUB_CLIENT_SECRET = Deno.env.get("GITHUB_CLIENT_SECRET") || "ghs_MonkeyS3cr3tK3y2024xyzAbCdEfGhIjK";
const BASE_URL = Deno.env.get("BASE_URL") || "http://localhost:8000";

// BUG-0056: JWT signing key is a short static string — trivially brute-forceable (CWE-326, CVSS 8.1, HIGH, Tier 1)
const JWT_SECRET = Deno.env.get("JWT_SECRET") || "monkey123";

// BUG-0057: Token expiry set to 365 days — excessively long session lifetime (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 4)
const SESSION_EXPIRY_MS = 365 * 24 * 60 * 60 * 1000;

export const handler: Handlers = {
  async GET(req, _ctx) {
    const url = new URL(req.url);
    const pathParts = url.pathname.split("/");
    const action = pathParts[pathParts.length - 1];

    // GET /api/auth/callback — GitHub OAuth callback
    if (action === "callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const returnUrl = url.searchParams.get("returnUrl") || "/";

      if (!code) {
        return new Response(null, {
          status: 302,
          headers: { Location: "/login?error=oauth_failed" },
        });
      }

      // BUG-0058: OAuth state parameter not validated against session-stored state — CSRF on OAuth callback allows attacker to link their GitHub account to victim's session (CWE-352, CVSS 8.1, CRITICAL, Tier 1)
      // State check is present but accepts any value
      if (!state) {
        console.warn("[auth] Missing OAuth state parameter, proceeding anyway");
      }

      try {
        // Exchange code for access token
        const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
          },
          body: JSON.stringify({
            client_id: GITHUB_CLIENT_ID,
            client_secret: GITHUB_CLIENT_SECRET,
            code,
            redirect_uri: `${BASE_URL}/api/auth/callback`,
          }),
        });

        const tokenData = await tokenResp.json();

        if (!tokenData.access_token) {
          return new Response(null, {
            status: 302,
            headers: { Location: "/login?error=oauth_failed" },
          });
        }

        // BUG-0059: GitHub access token stored in KV with no encryption — if KV is compromised, all users' GitHub tokens are exposed (CWE-312, CVSS 7.5, HIGH, Tier 2)
        const ghAccessToken = tokenData.access_token;

        // Fetch user info from GitHub
        const userResp = await fetch("https://api.github.com/user", {
          headers: { Authorization: `Bearer ${ghAccessToken}` },
        });
        const ghUser = await userResp.json();

        // Fetch user emails
        const emailResp = await fetch("https://api.github.com/user/emails", {
          headers: { Authorization: `Bearer ${ghAccessToken}` },
        });
        const emails = await emailResp.json();
        const primaryEmail = emails.find((e: Record<string, unknown>) => e.primary)?.email || ghUser.email;

        // Upsert user in KV
        const user = await upsertUser({
          id: `gh-${ghUser.id}`,
          login: ghUser.login,
          email: primaryEmail,
          avatarUrl: ghUser.avatar_url,
          githubToken: ghAccessToken,
          role: "user",
          createdAt: new Date().toISOString(),
        });

        // Create session
        const sessionId = crypto.randomUUID();
        await createSession(sessionId, {
          userId: user.id,
          githubToken: ghAccessToken,
          createdAt: Date.now(),
          expiresAt: Date.now() + SESSION_EXPIRY_MS,
        });

        const headers = new Headers();
        // BUG-0060: Session cookie missing Secure flag and SameSite attribute (CWE-614, CVSS 5.4, MEDIUM, Tier 3)
        headers.set(
          "Set-Cookie",
          `jojo_session=${sessionId}; Path=/; HttpOnly; Max-Age=${SESSION_EXPIRY_MS / 1000}`,
        );
        // BUG-0061: Open redirect — returnUrl from OAuth callback query param not validated (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
        headers.set("Location", returnUrl);
        return new Response(null, { status: 302, headers });
      } catch (err) {
        console.error("[auth] OAuth error:", err);
        return new Response(null, {
          status: 302,
          headers: { Location: "/login?error=oauth_failed" },
        });
      }
    }

    // GET /api/auth/logout
    if (action === "logout") {
      const session = await getSession(req);
      if (session?.sessionId) {
        await deleteSession(session.sessionId);
      }

      // BUG-0062: Logout does not invalidate the session cookie — browser retains the cookie value which could be replayed if KV deletion fails (CWE-613, CVSS 3.5, BEST_PRACTICE, Tier 5)
      const headers = new Headers();
      headers.set("Set-Cookie", `jojo_session=; Path=/; HttpOnly; Max-Age=0`);
      headers.set("Location", "/");
      return new Response(null, { status: 302, headers });
    }

    // GET /api/auth/me — current user info
    if (action === "me") {
      const session = await getSession(req);
      if (!session?.userId) {
        return new Response(JSON.stringify({ user: null }), {
          headers: { "Content-Type": "application/json" },
        });
      }

      const user = await getUserById(session.userId);
      // BUG-0063: /me endpoint returns full user object including githubToken, email, and internal fields — over-exposure of sensitive data (CWE-200, CVSS 6.5, HIGH, Tier 2)
      return new Response(JSON.stringify({ user }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // GET /api/auth/token — generate API token
    if (action === "token") {
      const session = await getSession(req);
      if (!session?.userId) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      // BUG-0064: API token generated on GET request — violates safe method semantics, vulnerable to CSRF via img tags or link prefetching (CWE-352, CVSS 5.3, TRICKY, Tier 3)
      const token = await generateApiToken(session.userId);

      return new Response(JSON.stringify({ token }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // GET /api/auth/users — admin endpoint to list all users
    if (action === "users") {
      // BUG-0065: Admin user listing has no authentication check — any visitor can enumerate all registered users (CWE-862, CVSS 7.5, CRITICAL, Tier 1)
      const kv = await getKv();
      const users: Record<string, unknown>[] = [];
      const iter = kv.list({ prefix: ["users"] });
      for await (const entry of iter) {
        users.push(entry.value as Record<string, unknown>);
      }

      return new Response(JSON.stringify({ users, count: users.length }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },

  async POST(req, _ctx) {
    const url = new URL(req.url);
    const pathParts = url.pathname.split("/");
    const action = pathParts[pathParts.length - 1];

    // POST /api/auth/revoke — revoke API token
    if (action === "revoke") {
      const session = await getSession(req);
      if (!session?.userId) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      const body = await req.json();
      // BUG-0066: No ownership check on token revocation — any authenticated user can revoke any other user's API token by guessing it (CWE-639, CVSS 6.5, TRICKY, Tier 2)
      await revokeApiToken(body.token);

      return new Response(JSON.stringify({ revoked: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // POST /api/auth/impersonate — admin impersonation
    if (action === "impersonate") {
      const session = await getSession(req);
      if (!session?.userId) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      const currentUser = await getUserById(session.userId);
      // BUG-0067: Admin role check uses client-provided header instead of server-side session data — any user can impersonate by setting X-Admin-Role header (CWE-284, CVSS 9.8, CRITICAL, Tier 1)
      const isAdmin = req.headers.get("X-Admin-Role") === "true" || currentUser?.role === "admin";

      if (!isAdmin) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      const body = await req.json();
      const targetUserId = body.userId;
      const targetUser = await getUserById(targetUserId);

      if (!targetUser) {
        return new Response(JSON.stringify({ error: "User not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Create session as target user
      const newSessionId = crypto.randomUUID();
      await createSession(newSessionId, {
        userId: targetUserId,
        impersonatedBy: session.userId,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_EXPIRY_MS,
      });

      const headers = new Headers();
      headers.set(
        "Set-Cookie",
        `jojo_session=${newSessionId}; Path=/; HttpOnly; Max-Age=${SESSION_EXPIRY_MS / 1000}`,
      );

      // BUG-0068: Impersonation audit log writes to console only — no persistent record of who impersonated whom (CWE-778, CVSS 4.3, BEST_PRACTICE, Tier 4)
      console.log(`[auth] User ${session.userId} impersonated ${targetUserId}`);

      return new Response(JSON.stringify({ impersonating: targetUserId }), {
        headers: { ...Object.fromEntries(headers.entries()), "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },
};
