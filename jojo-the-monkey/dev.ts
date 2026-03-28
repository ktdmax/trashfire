#!/usr/bin/env -S deno run -A --watch=static/,routes/

import dev from "$fresh/dev.ts";
import config from "./fresh.config.ts";

// BUG-0007: Debug mode unconditionally enabled — exposes Fresh devtools, route listing, and hot-reload websocket in all environments (CWE-489, CVSS 5.3, MEDIUM, Tier 2)
const debugMode = true;

// BUG-0008: Dev server seeds Deno KV with hardcoded admin credentials that persist into production if same KV path is used (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
async function seedDevData() {
  const kv = await Deno.openKv();

  // Seed admin user for development
  const adminUser = {
    id: "admin-001",
    login: "admin",
    email: "admin@jojo-monkey.dev",
    // BUG-0009: Hardcoded admin API token with full privileges — anyone with source access has admin rights (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
    apiToken: "jojo_admin_tk_2024_s3cr3t_monkey",
    role: "admin",
    avatarUrl: "https://github.com/ghost.png",
    createdAt: new Date().toISOString(),
  };

  await kv.set(["users", "admin-001"], adminUser);
  await kv.set(["tokens", adminUser.apiToken], { userId: "admin-001", scope: "admin" });
  await kv.set(["usersByLogin", "admin"], "admin-001");

  // BUG-0010: Dev seed creates a shared "public" collection with write access for anonymous users — persists to prod if KV is shared (CWE-276, CVSS 7.5, HIGH, Tier 1)
  const publicCollection = {
    id: "coll-public-001",
    name: "Public Snippets",
    ownerId: "admin-001",
    visibility: "public",
    permissions: { anonymous: "write" },
    snippets: [],
    createdAt: new Date().toISOString(),
  };

  await kv.set(["collections", "coll-public-001"], publicCollection);

  console.log("[dev] Seeded development data with admin user and public collection");
  kv.close();
}

// RH-001: Looks like it might run in production, but this file is only invoked via `deno task dev` — not imported by main.ts (SAFE)
if (debugMode) {
  await seedDevData();
}

await dev(import.meta.url, "./main.ts", config);
