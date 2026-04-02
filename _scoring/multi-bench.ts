#!/usr/bin/env npx tsx
/**
 * multi-bench.ts - Run benchmarks across multiple providers/models
 *
 * Usage:
 *   npx tsx multi-bench.ts --project grog-shop --preset thorough
 *   npx tsx multi-bench.ts --project grog-shop --preset vanilla --models all
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { buildCanonicalHeader } from "../_prompts/project-context.js";

const ROOT = join(import.meta.dirname ?? ".", "..");
const BLIND = join(ROOT, "_blind");
const MANIFESTS = join(ROOT, "_manifests");
const RESULTS = join(ROOT, "_results");
const SCORING = import.meta.dirname ?? ".";

// ── Load keys ──
function loadKeys(): Record<string, string> {
  const keyFile = join(ROOT, "test-keys.md");
  if (!existsSync(keyFile)) {
    console.error("test-keys.md not found. Create it with your API keys.");
    process.exit(1);
  }
  const raw = readFileSync(keyFile, "utf-8");
  const keys: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const m = line.match(/^([a-zA-Z]+)[\w_]*\s*:\s*(.+)/i);
    if (m) {
      let k = m[1].toLowerCase().trim();
      if (k === "antrophic") k = "anthropic";
      keys[k] = m[2].trim();
    }
  }
  console.log(`  Keys found: ${Object.keys(keys).join(", ")}`);
  return keys;
}

// ── Models ──
interface ModelDef {
  id: string;
  display: string;
  provider: "anthropic" | "openai" | "google" | "groq";
  apiModel: string;
}

const MODELS: ModelDef[] = [
  // Anthropic
  { id: "opus-4", display: "Claude Opus 4", provider: "anthropic", apiModel: "claude-opus-4-20250514" },
  { id: "sonnet-4", display: "Claude Sonnet 4", provider: "anthropic", apiModel: "claude-sonnet-4-20250514" },
  { id: "haiku-3.5", display: "Claude Haiku 3.5", provider: "anthropic", apiModel: "claude-3-5-haiku-latest" },
  // OpenAI
  { id: "gpt-4o", display: "GPT-4o", provider: "openai", apiModel: "gpt-4o" },
  { id: "gpt-4o-mini", display: "GPT-4o Mini", provider: "openai", apiModel: "gpt-4o-mini" },
  { id: "o3-mini", display: "o3-mini", provider: "openai", apiModel: "o3-mini" },
  // Google
  { id: "gemini-2.5-pro", display: "Gemini 2.5 Pro", provider: "google", apiModel: "gemini-2.5-pro-preview-06-05" },
  { id: "gemini-2.5-flash", display: "Gemini 2.5 Flash", provider: "google", apiModel: "gemini-2.5-flash-preview-05-20" },
  // Groq (open models)
  { id: "llama-3.3-70b", display: "Llama 3.3 70B", provider: "groq", apiModel: "llama-3.3-70b-versatile" },
  { id: "llama-3.1-8b", display: "Llama 3.1 8B", provider: "groq", apiModel: "llama-3.1-8b-instant" },
];

// ── Presets (Layer 2 additions — appended to base prompt) ──
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

// ── Collect project files ──
const SCAN_EXT = new Set([".ts",".tsx",".js",".jsx",".py",".go",".rs",".java",".kt",".scala",".rb",".erb",".php",".c",".cpp",".h",".cs",".swift",".ex",".exs",".hs",".jl",".r",".R",".pl",".pm",".zig",".sol",".dart",".svelte",".vue",".sql",".yaml",".yml",".toml",".json",".tf",".html",".css",".sh",".conf",".prisma",".proto",".env",".example",".ep"]);

function collectFiles(dir: string): { path: string; content: string }[] {
  const files: { path: string; content: string }[] = [];
  function walk(d: string) {
    for (const ent of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, ent.name);
      if (ent.isDirectory()) {
        if (!ent.name.startsWith(".") && ent.name !== "node_modules" && ent.name !== "__pycache__") walk(full);
      } else {
        const ext = extname(ent.name).toLowerCase();
        if (SCAN_EXT.has(ext) || ["Dockerfile","Makefile","Gemfile","cpanfile"].includes(ent.name)) {
          try {
            const content = readFileSync(full, "utf-8");
            if (content.length < 50000) { // skip huge files
              files.push({ path: relative(BLIND, full), content });
            }
          } catch {}
        }
      }
    }
  }
  walk(dir);
  return files;
}

// ── Build prompt with all files ──
function buildPrompt(project: string, preset: string, files: { path: string; content: string }[]): string {
  const fileBlock = files.map(f => `=== ${f.path} ===\n${f.content}`).join("\n\n");

  // Layer 0 + Layer 1 (canonical header)
  const canonicalHeader = buildCanonicalHeader(project);

  // Layer 2 (preset addition, empty for vanilla)
  const layer2 = LAYER2_PRESETS[preset] ?? preset;
  const layer2Block = layer2.trim() ? `\n\n---\n\n## Additional Review Guidance\n\n${layer2.trim()}` : "";

  return `${canonicalHeader}${layer2Block}

---

Here are all the files in the project:

${fileBlock}

=== END OF FILES ===`;
}

// ── API Calls ──

async function callAnthropic(apiKey: string, model: string, prompt: string): Promise<string> {
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 16000,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!resp.ok) throw new Error(`Anthropic ${resp.status}: ${await resp.text()}`);
  const data = await resp.json() as any;
  return data.content?.[0]?.text ?? "";
}

async function callOpenAI(apiKey: string, model: string, prompt: string): Promise<string> {
  const isO3 = model.startsWith("o3") || model.startsWith("o4");
  const body: any = { model, messages: [{ role: "user", content: prompt }] };
  if (isO3) { body.max_completion_tokens = 16000; } else { body.max_tokens = 16000; }
  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`OpenAI ${resp.status}: ${await resp.text()}`);
  const data = await resp.json() as any;
  return data.choices?.[0]?.message?.content ?? "";
}

async function callGemini(apiKey: string, model: string, prompt: string): Promise<string> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 16000 },
    }),
  });
  if (!resp.ok) throw new Error(`Gemini ${resp.status}: ${await resp.text()}`);
  const data = await resp.json() as any;
  return data.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
}

async function callGroq(apiKey: string, model: string, prompt: string): Promise<string> {
  const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      max_tokens: 16000,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!resp.ok) throw new Error(`Groq ${resp.status}: ${await resp.text()}`);
  const data = await resp.json() as any;
  return data.choices?.[0]?.message?.content ?? "";
}

async function callModel(model: ModelDef, keys: Record<string, string>, prompt: string): Promise<string> {
  switch (model.provider) {
    case "anthropic": return callAnthropic(keys.anthropic, model.apiModel, prompt);
    case "openai": return callOpenAI(keys.openai, model.apiModel, prompt);
    case "google": return callGemini(keys.gemini || keys.google, model.apiModel, prompt);
    case "groq": return callGroq(keys.groq, model.apiModel, prompt);
  }
}

// ── Extract JSON from response ──
function extractJSON(raw: string): any {
  // Try direct parse first
  try { return JSON.parse(raw); } catch {}
  // Find JSON block
  const m = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (m) try { return JSON.parse(m[1]); } catch {}
  // Find { ... findings ... }
  const m2 = raw.match(/\{[\s\S]*"findings"[\s\S]*\}/);
  if (m2) try { return JSON.parse(m2[0]); } catch {}
  return null;
}

// ── Score ──
import { spawnSync } from "node:child_process";

function scoreReview(project: string, reviewPath: string, passphrase: string): any {
  const manifestPath = join(MANIFESTS, `${project}.enc`);
  const reportPath = reviewPath.replace(/-review\.json$/, "-report.md");

  const result = spawnSync("npx", [
    "tsx", join(SCORING, "score.ts"),
    "--manifest", manifestPath,
    "--review", reviewPath,
    "--output", reportPath,
  ], { input: passphrase + "\n", encoding: "utf-8", timeout: 60000 });

  const jsonPath = reportPath.replace(/\.md$/, ".json");
  if (existsSync(jsonPath)) {
    return JSON.parse(readFileSync(jsonPath, "utf-8"));
  }
  return null;
}

// ── Main ──
async function main() {
  const args = process.argv.slice(2);
  const get = (f: string) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : undefined; };

  const project = get("--project") ?? "grog-shop";
  const preset = get("--preset") ?? "thorough";
  const modelFilter = get("--models") ?? "all";
  const passphrase = get("--passphrase") ?? process.env.TRASHFIRE_KEY ?? "";

  const keys = loadKeys();

  // Filter models
  let models = MODELS;
  if (modelFilter !== "all") {
    const ids = modelFilter.split(",");
    models = MODELS.filter(m => ids.includes(m.id) || ids.includes(m.provider));
  }

  // Check which providers have keys
  models = models.filter(m => {
    const keyLookup = m.provider === "google" ? "gemini" : m.provider;
    if (!keys[keyLookup] && !keys[m.provider]) {
      console.log(`  SKIP ${m.display}: no ${m.provider} API key`);
      return false;
    }
    return true;
  });

  console.log(`\n  TRASHFIRE Multi-Provider Benchmark`);
  console.log(`  ====================================`);
  console.log(`  Project: ${project}`);
  console.log(`  Preset:  ${preset}`);
  console.log(`  Models:  ${models.length}`);
  console.log(`  ====================================\n`);

  // Collect files
  const projectDir = join(BLIND, project);
  if (!existsSync(projectDir)) {
    console.error(`  Project not found: ${projectDir}`);
    console.error(`  Run: bash _scoring/create-blind-copy.sh`);
    process.exit(1);
  }

  console.log(`  Collecting files from ${project}...`);
  const files = collectFiles(projectDir);
  console.log(`  ${files.length} files, ${files.reduce((s, f) => s + f.content.length, 0)} chars total\n`);

  // Run each model
  const results: any[] = [];

  for (const model of models) {
    const runId = `${preset}-${model.id}-${project}-${Date.now().toString(36)}`;
    const runDir = join(RESULTS, runId);
    mkdirSync(runDir, { recursive: true });

    console.log(`  [${models.indexOf(model) + 1}/${models.length}] ${model.display} (${model.provider})`);

    // Trim files for models with small context windows
    let modelFiles = files;
    const maxChars = model.provider === "groq" ? 15000 : 120000;
    let total = files.reduce((s, f) => s + f.content.length, 0);
    if (total > maxChars) {
      modelFiles = [];
      let acc = 0;
      // Prioritize largest files (most code = most bugs)
      const sorted = [...files].sort((a, b) => b.content.length - a.content.length);
      for (const f of sorted) {
        if (acc + f.content.length > maxChars) break;
        modelFiles.push(f);
        acc += f.content.length;
      }
      console.log(`    (trimmed to ${modelFiles.length}/${files.length} files, ${(acc/1000).toFixed(0)}k chars)`);
    }

    const prompt = buildPrompt(project, preset, modelFiles);
    const startTime = Date.now();
    try {
      const raw = await callModel(model, keys, prompt);
      const duration = Date.now() - startTime;
      console.log(`    Response in ${(duration / 1000).toFixed(1)}s (${raw.length} chars)`);

      // Save raw
      writeFileSync(join(runDir, "raw-response.txt"), raw);

      // Extract JSON
      const parsed = extractJSON(raw);
      if (!parsed || !parsed.findings) {
        console.log(`    WARN: Could not extract findings JSON`);
        const empty = { reviewer: model.display, project, timestamp: new Date().toISOString(), findings: [] };
        writeFileSync(join(runDir, `${project}-review.json`), JSON.stringify(empty, null, 2));
      } else {
        parsed.reviewer = model.display;
        writeFileSync(join(runDir, `${project}-review.json`), JSON.stringify(parsed, null, 2));
        console.log(`    ${parsed.findings.length} findings extracted`);
      }

      // Score
      const reviewPath = join(runDir, `${project}-review.json`);
      const score = scoreReview(project, reviewPath, passphrase);
      if (score) {
        console.log(`    SCORE: ${(score.composite_score * 100).toFixed(1)}% (${score.matched_issues}/${score.total_issues} found, ${score.false_positives} FP)`);
        results.push({
          model: model.display, provider: model.provider, preset,
          score: score.composite_score, found: score.matched_issues, total: score.total_issues,
          fp: score.false_positives, rh: score.red_herrings_flagged,
          duration_ms: duration, run_id: runId,
        });
      }
    } catch (err: any) {
      console.log(`    ERROR: ${err.message.slice(0, 200)}`);
      results.push({
        model: model.display, provider: model.provider, preset,
        score: 0, found: 0, total: 100, fp: 0, rh: 0,
        duration_ms: Date.now() - startTime, run_id: runId, error: err.message.slice(0, 200),
      });
    }

    console.log();
  }

  // Summary
  console.log(`  ====================================`);
  console.log(`  RESULTS SUMMARY`);
  console.log(`  ====================================`);
  console.log(`  ${"Model".padEnd(25)} ${"Score".padStart(8)} ${"Found".padStart(8)} ${"FP".padStart(5)} ${"Time".padStart(8)}`);
  console.log(`  ${"-".repeat(56)}`);

  results.sort((a, b) => b.score - a.score);
  for (const r of results) {
    const time = r.duration_ms < 60000 ? `${(r.duration_ms/1000).toFixed(0)}s` : `${(r.duration_ms/60000).toFixed(1)}m`;
    console.log(`  ${r.model.padEnd(25)} ${((r.score*100).toFixed(1)+"%").padStart(8)} ${(r.found+"/"+r.total).padStart(8)} ${String(r.fp).padStart(5)} ${time.padStart(8)}`);
  }
  console.log(`  ====================================\n`);

  // Save summary
  const summaryPath = join(RESULTS, `multi-bench-${project}-${preset}-${Date.now().toString(36)}.json`);
  writeFileSync(summaryPath, JSON.stringify({ project, preset, timestamp: new Date().toISOString(), results }, null, 2));
  console.log(`  Summary: ${summaryPath}`);
}

main().catch(err => { console.error(err); process.exit(1); });
