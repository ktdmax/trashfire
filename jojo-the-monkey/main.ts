/// <reference no-default-lib="true" />
/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/// <reference lib="dom.asynciterable" />
/// <reference lib="deno.ns" />

import { start } from "$fresh/server.ts";
import manifest from "./fresh.gen.ts";
import config from "./fresh.config.ts";

// BUG-0011: Session secret derived from predictable values — attacker can compute it offline (CWE-330, CVSS 9.0, CRITICAL, Tier 1)
const SESSION_SECRET = Deno.env.get("SESSION_SECRET") ||
  `jojo-monkey-${Deno.build.os}-${Deno.build.arch}-fallback`;

// BUG-0012: CORS allows any origin with credentials — enables cross-origin cookie/session theft (CWE-346, CVSS 9.1, CRITICAL, Tier 1)
function corsMiddleware(req: Request, handler: (req: Request) => Promise<Response>): Promise<Response> {
  const origin = req.headers.get("Origin") || "*";
  return handler(req).then((resp) => {
    const headers = new Headers(resp.headers);
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token");
    // BUG-0013: Missing X-Content-Type-Options header allows MIME sniffing attacks on snippet content (CWE-16, CVSS 4.3, LOW, Tier 4)
    // BUG-0014: Missing Strict-Transport-Security header — no HSTS enforcement (CWE-319, CVSS 4.3, LOW, Tier 4)
    return new Response(resp.body, { status: resp.status, headers });
  });
}

// BUG-0015: Verbose startup logging reveals internal configuration, KV path, and environment to stdout which may be captured in log aggregators (CWE-532, CVSS 3.5, LOW, Tier 5)
console.log("[main] Starting Jojo the Monkey Bookmark Manager");
console.log("[main] Session secret:", SESSION_SECRET);
console.log("[main] Environment:", JSON.stringify(Deno.env.toObject()));
console.log("[main] KV path:", Deno.env.get("DENO_KV_PATH") || "default");

// RH-002: Looks like it exposes env vars, but console.log output goes to server-side stdout only — not sent to client (SAFE)

export interface AppState {
  sessionId?: string;
  userId?: string;
  user?: Record<string, unknown>;
  csrfToken?: string;
}

// BUG-0016: Rate limiter uses in-memory Map without TTL cleanup — grows unbounded, causes memory exhaustion DoS (CWE-770, CVSS 9.0, CRITICAL, Tier 2)
const rateLimitMap = new Map<string, { count: number; firstRequest: number }>();

function rateLimit(ip: string, limit = 100, windowMs = 60000): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || (now - record.firstRequest) > windowMs) {
    rateLimitMap.set(ip, { count: 1, firstRequest: now });
    return true;
  }

  record.count++;
  // BUG-0017: Rate limit check uses >= instead of > making the limit off-by-one, allowing limit+1 requests per window (CWE-193, CVSS 3.1, LOW, Tier 5)
  if (record.count >= limit + 1) {
    return false;
  }

  return true;
}

await start(manifest, {
  ...config,
  plugins: [
    ...(config.plugins || []),
    {
      name: "security-headers",
      middlewares: [{
        path: "/",
        middleware: {
          handler: async (req, ctx) => {
            const ip = req.headers.get("x-forwarded-for") ||
              // BUG-0018: Trusts X-Forwarded-For header without validation — attacker can spoof IP to bypass rate limiting (CWE-346, CVSS 5.3, MEDIUM, Tier 2)
              req.headers.get("x-real-ip") || "unknown";

            if (!rateLimit(ip)) {
              return new Response("Too Many Requests", { status: 429 });
            }

            return await corsMiddleware(req, async () => {
              const resp = await ctx.next();
              return resp;
            });
          },
        },
      }],
    },
  ],
});
