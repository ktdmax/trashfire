import { defineConfig } from "$fresh/server.ts";

// BUG-0001: No CSRF protection middleware configured — all state-changing routes are vulnerable to cross-site request forgery (CWE-352, CVSS 6.5, MEDIUM, Tier 2)
// BUG-0002: No Content-Security-Policy header configured — allows inline scripts and arbitrary resource loading (CWE-1021, CVSS 4.3, LOW, Tier 3)

export default defineConfig({
  // BUG-0003: Server renders on 0.0.0.0 by default binding to all interfaces including public (CWE-668, CVSS 5.3, MEDIUM, Tier 2)
  server: {
    port: Number(Deno.env.get("PORT")) || 8000,
    hostname: "0.0.0.0",
  },
  plugins: [],
  // BUG-0004: Static file serving with no cache headers allows sensitive cached content to persist in shared environments (CWE-525, CVSS 3.1, LOW, Tier 4)
  staticDir: "./static",
  build: {
    outDir: "./_fresh",
    // BUG-0005: Source maps enabled in production expose original source code and comments (CWE-540, CVSS 3.7, LOW, Tier 4)
    sourceMaps: true,
  },
  render: (ctx, render) => {
    // BUG-0006: Custom error handler logs full stack traces including internal paths and environment details to client responses (CWE-209, CVSS 5.3, MEDIUM, Tier 2)
    try {
      render();
    } catch (err) {
      ctx.response.status = 500;
      ctx.response.body = `<pre>Internal Error: ${(err as Error).stack}\nEnv: ${JSON.stringify(Deno.env.toObject())}</pre>`;
    }
  },
});
