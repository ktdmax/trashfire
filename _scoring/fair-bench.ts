#!/usr/bin/env npx tsx
/**
 * fair-bench.ts - Fair multi-model benchmark
 *
 * Principles:
 *   1. Every model receives the EXACT same input (prompt + files)
 *   2. Input is hashed - provably identical across all runs
 *   3. API errors are retried (3 attempts), not counted as 0
 *   4. Models that can't handle the input size are excluded, not trimmed
 *   5. Results include the input hash for reproducibility
 *
 * Usage:
 *   npx tsx fair-bench.ts --project grog-shop --preset thorough
 *   npx tsx fair-bench.ts --project grog-shop --preset vanilla --models anthropic,openai
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { buildCanonicalHeader } from "../_prompts/project-context.js";

const ROOT = join(import.meta.dirname ?? ".", "..");
const BLIND = join(ROOT, "_blind");
const MANIFESTS = join(ROOT, "_manifests");
const RESULTS = join(ROOT, "_results");
const SCORING = import.meta.dirname ?? ".";

// ─── Keys ────────────────────────────────────────────────────────────────────

function loadKeys(): Record<string, string> {
  const p = join(ROOT, "test-keys.md");
  if (!existsSync(p)) { console.error("test-keys.md not found"); process.exit(1); }
  const keys: Record<string, string> = {};
  for (const line of readFileSync(p, "utf-8").split("\n")) {
    const m = line.match(/^([a-zA-Z]+)[\w_]*\s*:\s*(\S+)/);
    if (m) {
      let k = m[1].toLowerCase();
      if (k === "antrophic") k = "anthropic";
      keys[k] = m[2].trim();
    }
  }
  return keys;
}

// ─── Models ──────────────────────────────────────────────────────────────────

interface Model {
  id: string;
  name: string;
  provider: "anthropic" | "openai" | "google" | "groq";
  api: string;
  contextTokens: number; // approximate max input tokens
}

const ALL_MODELS: Model[] = [
  // Anthropic (200k context)
  { id: "opus-4", name: "Claude Opus 4", provider: "anthropic", api: "claude-opus-4-20250514", contextTokens: 200000 },
  { id: "sonnet-4", name: "Claude Sonnet 4", provider: "anthropic", api: "claude-sonnet-4-20250514", contextTokens: 200000 },
  { id: "haiku-3.5", name: "Claude Haiku 3.5", provider: "anthropic", api: "claude-3-5-haiku-20241022", contextTokens: 200000 },
  // OpenAI (128k context)
  { id: "gpt-4o", name: "GPT-4o", provider: "openai", api: "gpt-4o", contextTokens: 128000 },
  { id: "gpt-4o-mini", name: "GPT-4o Mini", provider: "openai", api: "gpt-4o-mini", contextTokens: 128000 },
  { id: "o3-mini", name: "o3-mini", provider: "openai", api: "o3-mini", contextTokens: 128000 },
  // Google (1M context)
  { id: "gemini-2.5-flash", name: "Gemini 2.5 Flash", provider: "google", api: "gemini-2.5-flash", contextTokens: 1000000 },
  { id: "gemini-2.5-pro", name: "Gemini 2.5 Pro", provider: "google", api: "gemini-2.5-pro", contextTokens: 1000000 },
  // Groq (smaller context, rate limited)
  { id: "llama-3.3-70b", name: "Llama 3.3 70B (Groq)", provider: "groq", api: "llama-3.3-70b-versatile", contextTokens: 32000 },
];

// ─── Presets (Layer 2 additions — appended to base prompt) ──────────────────
// Every run gets Layer 0 (base-review.md) + Layer 1 (project context).
// Presets add Layer 2 methodology/focus text. Vanilla = empty.

const LAYER2_PRESETS: Record<string, string> = {
  vanilla: "",
  security: `Focus extra attention on security vulnerabilities. For each file:
- Map data flows from untrusted inputs to sensitive operations
- Check authentication and authorization at every boundary
- Look for injection vectors: SQL, command, template, deserialization
- Verify cryptographic operations use strong algorithms and proper parameters
- Check for hardcoded secrets, debug endpoints, and permissive CORS`,
  thorough: `Think like an experienced senior developer who has seen production incidents.
Pay special attention to edge cases: empty arrays, negative numbers, Unicode input,
concurrent requests, float arithmetic for money, TOCTOU problems, missing permission
checks, error paths that skip cleanup, and state transitions that can be triggered
out of order.`,
};

// ─── Collect files ───────────────────────────────────────────────────────────

const EXT = new Set([".ts",".tsx",".js",".jsx",".py",".go",".rs",".java",".kt",".scala",".rb",".erb",".php",".c",".cpp",".h",".cs",".swift",".ex",".exs",".hs",".jl",".r",".R",".pl",".pm",".zig",".sol",".dart",".svelte",".vue",".sql",".yaml",".yml",".toml",".json",".tf",".html",".css",".sh",".conf",".prisma",".proto",".env",".example",".ep"]);

function collectFiles(dir: string): { path: string; content: string }[] {
  const files: { path: string; content: string }[] = [];
  function walk(d: string) {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const f = join(d, e.name);
      if (e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "__pycache__") walk(f);
      else if (e.isFile()) {
        const ext = extname(e.name).toLowerCase();
        if (EXT.has(ext) || ["Dockerfile","Makefile","Gemfile","cpanfile"].includes(e.name)) {
          try { const c = readFileSync(f, "utf-8"); if (c.length < 50000) files.push({ path: relative(BLIND, f), content: c }); } catch {}
        }
      }
    }
  }
  walk(dir);
  return files.sort((a, b) => a.path.localeCompare(b.path)); // deterministic order
}

// ─── Build the EXACT prompt (frozen, hashed) ─────────────────────────────────

interface FrozenInput {
  prompt: string;
  hash: string;
  approxTokens: number;
}

function buildFrozenInput(project: string, preset: string, files: { path: string; content: string }[]): FrozenInput {
  const fileBlock = files.map(f => `=== FILE: ${f.path} ===\n${f.content}`).join("\n\n");

  // Layer 0 + Layer 1 (canonical header)
  const canonicalHeader = buildCanonicalHeader(project);

  // Layer 2 (preset addition, empty for vanilla)
  const layer2 = LAYER2_PRESETS[preset] ?? preset;
  const layer2Block = layer2.trim() ? `\n\n---\n\n## Additional Review Guidance\n\n${layer2.trim()}` : "";

  const prompt = `${canonicalHeader}${layer2Block}

---

Here are all the source files in the "${project}" project:

${fileBlock}

=== END OF FILES ===`;

  const hash = createHash("sha256").update(prompt).digest("hex");
  const approxTokens = Math.ceil(prompt.length / 3.5); // rough estimate

  return { prompt, hash, approxTokens };
}

// ─── API Calls (with retry) ──────────────────────────────────────────────────

const MAX_RETRIES = 3;
const RETRY_DELAY = 5000;

async function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

async function callWithRetry(fn: () => Promise<string>, modelName: string): Promise<string> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      const msg = err.message || String(err);
      // Don't retry on model-not-found or auth errors
      if (msg.includes("404") || msg.includes("401") || msg.includes("not_found") || msg.includes("invalid_api_key")) {
        throw err;
      }
      if (attempt < MAX_RETRIES) {
        console.log(`    Retry ${attempt}/${MAX_RETRIES} for ${modelName}: ${msg.slice(0, 80)}`);
        await sleep(RETRY_DELAY * attempt);
      } else {
        throw err;
      }
    }
  }
  throw new Error("unreachable");
}

async function callAnthropic(key: string, model: string, prompt: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 300000); // 5 min timeout
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    signal: controller.signal,
    headers: { "Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model, max_tokens: 16000, messages: [{ role: "user", content: prompt }] }),
  });
  clearTimeout(timeout);
  if (!r.ok) throw new Error(`Anthropic ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json() as any;
  return d.content?.[0]?.text ?? "";
}

async function callOpenAI(key: string, model: string, prompt: string): Promise<string> {
  const isReasoning = model.startsWith("o3") || model.startsWith("o4");
  const body: any = { model, messages: [{ role: "user", content: prompt }] };
  if (isReasoning) body.max_completion_tokens = 16000; else body.max_tokens = 16000;
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`OpenAI ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json() as any;
  return d.choices?.[0]?.message?.content ?? "";
}

async function callGemini(key: string, model: string, prompt: string): Promise<string> {
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 16000 } }),
  });
  if (!r.ok) throw new Error(`Gemini ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json() as any;
  return d.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
}

async function callGroq(key: string, model: string, prompt: string): Promise<string> {
  const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
    body: JSON.stringify({ model, max_tokens: 8000, messages: [{ role: "user", content: prompt }] }),
  });
  if (!r.ok) throw new Error(`Groq ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json() as any;
  return d.choices?.[0]?.message?.content ?? "";
}

async function callModel(m: Model, keys: Record<string, string>, prompt: string): Promise<string> {
  const fn = () => {
    switch (m.provider) {
      case "anthropic": return callAnthropic(keys.anthropic, m.api, prompt);
      case "openai": return callOpenAI(keys.openai, m.api, prompt);
      case "google": return callGemini(keys.gemini, m.api, prompt);
      case "groq": return callGroq(keys.groq, m.api, prompt);
    }
  };
  return callWithRetry(fn, m.name);
}

// ─── JSON extraction ─────────────────────────────────────────────────────────

function extractFindings(raw: string): any[] | null {
  // Try direct parse
  try { const p = JSON.parse(raw); return p.findings ?? null; } catch {}
  // Try markdown code block
  const m1 = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (m1) try { const p = JSON.parse(m1[1]); return p.findings ?? null; } catch {}
  // Try finding { ... "findings" ... }
  const m2 = raw.match(/\{[\s\S]*"findings"\s*:\s*\[[\s\S]*\]\s*\}/);
  if (m2) try { const p = JSON.parse(m2[0]); return p.findings ?? null; } catch {}
  return null;
}

// ─── Score ───────────────────────────────────────────────────────────────────

function scoreReview(project: string, reviewPath: string, passphrase: string): any | null {
  const manifest = join(MANIFESTS, `${project}.enc`);
  const report = reviewPath.replace(/-review\.json$/, "-report.md");
  spawnSync("npx", ["tsx", join(SCORING, "score.ts"), "--manifest", manifest, "--review", reviewPath, "--output", report],
    { input: passphrase + "\n", encoding: "utf-8", timeout: 60000 });
  const jsonPath = report.replace(/\.md$/, ".json");
  if (existsSync(jsonPath)) return JSON.parse(readFileSync(jsonPath, "utf-8"));
  return null;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const get = (f: string) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : undefined; };

  const project = get("--project") ?? "grog-shop";
  const preset = get("--preset") ?? "thorough";
  const modelFilter = get("--models") ?? "all";
  const passphrase = get("--passphrase") ?? process.env.TRASHFIRE_KEY ?? "";

  const keys = loadKeys();

  // 1. Collect files and build frozen input
  const projectDir = join(BLIND, project);
  if (!existsSync(projectDir)) { console.error(`Not found: ${projectDir}\nRun: bash _scoring/create-blind-copy.sh`); process.exit(1); }

  const files = collectFiles(projectDir);
  const input = buildFrozenInput(project, preset, files);

  console.log();
  console.log(`  TRASHFIRE Fair Benchmark`);
  console.log(`  ========================`);
  console.log(`  Project:      ${project}`);
  console.log(`  Preset:       ${preset}`);
  console.log(`  Files:        ${files.length}`);
  console.log(`  Input chars:  ${input.prompt.length.toLocaleString()}`);
  console.log(`  Input tokens: ~${input.approxTokens.toLocaleString()}`);
  console.log(`  Input hash:   ${input.hash.slice(0, 16)}`);
  console.log(`  ========================`);

  // 2. Filter models: must have key AND enough context
  let models = ALL_MODELS;
  if (modelFilter !== "all") {
    const ids = modelFilter.split(",");
    models = ALL_MODELS.filter(m => ids.includes(m.id) || ids.includes(m.provider));
  }

  const eligible: Model[] = [];
  const excluded: { model: string; reason: string }[] = [];

  for (const m of models) {
    const keyName = m.provider === "google" ? "gemini" : m.provider;
    if (!keys[keyName] && !keys[m.provider]) {
      excluded.push({ model: m.name, reason: `no ${m.provider} API key` });
      continue;
    }
    if (input.approxTokens > m.contextTokens * 0.8) { // 80% safety margin
      excluded.push({ model: m.name, reason: `input (~${input.approxTokens.toLocaleString()} tokens) exceeds context (${m.contextTokens.toLocaleString()})` });
      continue;
    }
    eligible.push(m);
  }

  console.log(`\n  Eligible: ${eligible.length} models`);
  for (const m of eligible) console.log(`    + ${m.name} (${m.provider})`);
  if (excluded.length > 0) {
    console.log(`\n  Excluded:`);
    for (const e of excluded) console.log(`    - ${e.model}: ${e.reason}`);
  }
  console.log();

  // 3. Run benchmark
  const runId = `fair-${preset}-${project}-${Date.now().toString(36)}`;
  const runDir = join(RESULTS, runId);
  mkdirSync(runDir, { recursive: true });

  // Save frozen input hash (not the full prompt - that contains code)
  writeFileSync(join(runDir, "input-meta.json"), JSON.stringify({
    project, preset, files: files.length, chars: input.prompt.length,
    approx_tokens: input.approxTokens, hash: input.hash,
    file_list: files.map(f => f.path),
  }, null, 2));

  interface RunResult {
    model: string;
    provider: string;
    score: number;
    found: number;
    total: number;
    fp: number;
    rh: number;
    findings: number;
    duration_ms: number;
    status: "ok" | "error";
    error?: string;
    by_category?: Record<string, any>;
  }

  const results: RunResult[] = [];

  for (let i = 0; i < eligible.length; i++) {
    const m = eligible[i];
    console.log(`  [${i + 1}/${eligible.length}] ${m.name}`);

    const t0 = Date.now();
    try {
      const raw = await callModel(m, keys, input.prompt);
      const dur = Date.now() - t0;
      console.log(`    Response: ${(dur / 1000).toFixed(1)}s, ${raw.length} chars`);

      writeFileSync(join(runDir, `${m.id}-raw.txt`), raw);

      const findings = extractFindings(raw);
      if (!findings) {
        console.log(`    FAIL: Could not extract findings JSON`);
        results.push({ model: m.name, provider: m.provider, score: 0, found: 0, total: 0, fp: 0, rh: 0, findings: 0, duration_ms: dur, status: "error", error: "no JSON in response" });
        continue;
      }

      console.log(`    ${findings.length} findings`);

      // Write review file for scoring
      const reviewPath = join(runDir, `${m.id}-review.json`);
      writeFileSync(reviewPath, JSON.stringify({
        reviewer: m.name, project, timestamp: new Date().toISOString(), findings,
      }, null, 2));

      // Score
      const score = scoreReview(project, reviewPath, passphrase);
      if (score) {
        const r: RunResult = {
          model: m.name, provider: m.provider,
          score: score.composite_score,
          found: score.matched_issues, total: score.total_issues,
          fp: score.false_positives, rh: score.red_herrings_flagged,
          findings: findings.length, duration_ms: dur, status: "ok",
          by_category: score.by_category,
        };
        results.push(r);
        console.log(`    SCORE: ${(r.score * 100).toFixed(1)}% | Found: ${r.found}/${r.total} | FP: ${r.fp}`);
      } else {
        results.push({ model: m.name, provider: m.provider, score: 0, found: 0, total: 0, fp: 0, rh: 0, findings: findings.length, duration_ms: dur, status: "error", error: "scoring failed" });
      }
    } catch (err: any) {
      const dur = Date.now() - t0;
      console.log(`    ERROR: ${err.message.slice(0, 150)}`);
      results.push({ model: m.name, provider: m.provider, score: 0, found: 0, total: 0, fp: 0, rh: 0, findings: 0, duration_ms: dur, status: "error", error: err.message.slice(0, 200) });
    }
    console.log();
  }

  // 4. Summary
  const ok = results.filter(r => r.status === "ok").sort((a, b) => b.score - a.score);
  const err = results.filter(r => r.status === "error");

  console.log(`  ================================================================`);
  console.log(`  RESULTS  -  Project: ${project} | Preset: ${preset}`);
  console.log(`  Input hash: ${input.hash.slice(0, 16)} (identical for all models)`);
  console.log(`  ================================================================`);
  console.log();
  console.log(`  ${"#".padStart(3)} ${"Model".padEnd(25)} ${"Score".padStart(8)} ${"Found".padStart(8)} ${"FP".padStart(5)} ${"Time".padStart(8)}`);
  console.log(`  ${"---".padStart(3)} ${"".padEnd(25,"-")} ${"".padStart(8,"-")} ${"".padStart(8,"-")} ${"".padStart(5,"-")} ${"".padStart(8,"-")}`);

  ok.forEach((r, i) => {
    const time = r.duration_ms < 60000 ? `${(r.duration_ms / 1000).toFixed(0)}s` : `${(r.duration_ms / 60000).toFixed(1)}m`;
    console.log(`  ${String(i + 1).padStart(3)} ${r.model.padEnd(25)} ${(((r.score * 100).toFixed(1)) + "%").padStart(8)} ${(r.found + "/" + r.total).padStart(8)} ${String(r.fp).padStart(5)} ${time.padStart(8)}`);
  });

  if (err.length > 0) {
    console.log();
    console.log(`  Errors (${err.length}):`);
    err.forEach(r => console.log(`    ${r.model}: ${r.error}`));
  }

  console.log();
  console.log(`  ================================================================`);

  // 5. Save
  const summary = {
    run_id: runId,
    timestamp: new Date().toISOString(),
    project, preset,
    input_hash: input.hash,
    input_tokens: input.approxTokens,
    files: files.length,
    eligible_models: eligible.length,
    excluded: excluded,
    results: ok,
    errors: err,
  };
  const summaryPath = join(runDir, "summary.json");
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  console.log(`  Saved: ${summaryPath}`);
}

main().catch(e => { console.error(e); process.exit(1); });
