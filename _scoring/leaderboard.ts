#!/usr/bin/env npx tsx
/**
 * leaderboard.ts  - Generate shareable leaderboard from benchmark results
 *
 * Usage:
 *   npx tsx leaderboard.ts [--format md|json|html] [--out <path>]
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname ?? ".", "..");
const RESULTS_DIR = join(ROOT, "_results");
const INDEX_PATH = join(RESULTS_DIR, "results-index.json");

interface IndexEntry {
  run_id: string;
  timestamp: string;
  model: string;
  model_display: string;
  provider: string;
  preset: string;
  skills: string[];
  skill_source: string;
  projects_tested: number;
  composite_score: number;
  recall: number;
  precision: number;
  found: number;
  total: number;
  false_positives: number;
  duration_ms: number;
  tags: string[];
}

function loadIndex(): IndexEntry[] {
  if (!existsSync(INDEX_PATH)) return [];
  return JSON.parse(readFileSync(INDEX_PATH, "utf-8"));
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

function medal(rank: number): string {
  if (rank === 0) return "🥇";
  if (rank === 1) return "🥈";
  if (rank === 2) return "🥉";
  return `#${rank + 1}`;
}

function skillLabel(entry: IndexEntry): string {
  if (entry.skills.length === 0) return " -";
  if (entry.skill_source === "superpowers") return "Superpowers";
  if (entry.skill_source === "supaskills") return entry.skills.length > 1 ? `SupaSkills ×${entry.skills.length}` : "SupaSkills";
  return entry.skills.join(", ");
}

function duration(ms: number): string {
  if (ms === 0) return " -";
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

// ─── Markdown Leaderboard ────────────────────────────────────────────────────

function generateMarkdown(entries: IndexEntry[]): string {
  const lines: string[] = [];

  lines.push(`# 🔥 TRASHFIRE Benchmark Leaderboard`);
  lines.push(``);
  lines.push(`> AI Code Review Benchmark  - ${entries.length} runs across ${new Set(entries.map(e => e.model)).size} models`);
  lines.push(`>`);
  lines.push(`> Last updated: ${new Date().toISOString().split("T")[0]}`);
  lines.push(``);

  // Summary badges
  const best = entries[0];
  if (best) {
    lines.push(`**Current Leader:** ${best.model_display} (${best.preset})  - **${pct(best.composite_score)}**`);
    lines.push(``);
  }

  // Main leaderboard table
  lines.push(`## Overall Rankings`);
  lines.push(``);
  lines.push(`| Rank | Model | Prompt | Skills | Score | Recall | Precision | FP | Projects |`);
  lines.push(`|:----:|-------|--------|--------|------:|-------:|----------:|---:|:--------:|`);

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    lines.push(`| ${medal(i)} | **${e.model_display}** | ${e.preset} | ${skillLabel(e)} | **${pct(e.composite_score)}** | ${pct(e.recall)} | ${pct(e.precision)} | ${e.false_positives} | ${e.projects_tested} |`);
  }

  lines.push(``);

  // By Model comparison (group by model, best score each)
  const byModel = new Map<string, IndexEntry>();
  for (const e of entries) {
    const existing = byModel.get(e.model_display);
    if (!existing || e.composite_score > existing.composite_score) {
      byModel.set(e.model_display, e);
    }
  }

  if (byModel.size > 1) {
    lines.push(`## Best Score per Model`);
    lines.push(``);
    lines.push(`| Model | Best Score | Best Preset | Recall | Precision |`);
    lines.push(`|-------|----------:|-------------|-------:|----------:|`);

    const sorted = [...byModel.entries()].sort((a, b) => b[1].composite_score - a[1].composite_score);
    for (const [name, e] of sorted) {
      lines.push(`| **${name}** | **${pct(e.composite_score)}** | ${e.preset} | ${pct(e.recall)} | ${pct(e.precision)} |`);
    }
    lines.push(``);
  }

  // By Preset comparison
  const byPreset = new Map<string, IndexEntry[]>();
  for (const e of entries) {
    const list = byPreset.get(e.preset) ?? [];
    list.push(e);
    byPreset.set(e.preset, list);
  }

  if (byPreset.size > 1) {
    lines.push(`## Average Score per Prompt Strategy`);
    lines.push(``);
    lines.push(`| Strategy | Avg Score | Runs | Best | Worst |`);
    lines.push(`|----------|----------:|-----:|-----:|------:|`);

    const presetStats = [...byPreset.entries()].map(([name, runs]) => {
      const scores = runs.map(r => r.composite_score);
      const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
      return { name, avg, count: runs.length, best: Math.max(...scores), worst: Math.min(...scores) };
    }).sort((a, b) => b.avg - a.avg);

    for (const p of presetStats) {
      lines.push(`| **${p.name}** | **${pct(p.avg)}** | ${p.count} | ${pct(p.best)} | ${pct(p.worst)} |`);
    }
    lines.push(``);
  }

  // Methodology
  lines.push(`## Methodology`);
  lines.push(``);
  lines.push(`- **42 projects** across 30+ languages/frameworks`);
  lines.push(`- **~4,200 planted issues** (security, logic, performance, best practices, code smells, tricky cross-module bugs)`);
  lines.push(`- **~300 red herrings** (code that looks vulnerable but is safe)`);
  lines.push(`- **Scoring:** Detection (1pt) + Severity (0.5) + CWE (0.5) + Location (0.5) + Fix (1.0) + Explanation (0.5)`);
  lines.push(`- **Difficulty multipliers:** Tier 1 (×1.0) → Tier 5 (×3.0)`);
  lines.push(`- **Category weights:** SEC 35% | TRICKY 25% | LOGIC 20% | PERF 10% | BP 5% | SMELL 5%`);
  lines.push(`- **Penalties:** -1.0 per false positive, -2.0 per flagged red herring`);
  lines.push(`- **Ground truth** encrypted with AES-256-GCM, unavailable to reviewers during testing`);
  lines.push(``);
  lines.push(`## How to Run`);
  lines.push(``);
  lines.push("```bash");
  lines.push(`# Run a benchmark`);
  lines.push(`npx tsx _scoring/benchmark.ts --preset vanilla --project grog-shop`);
  lines.push(`npx tsx _scoring/benchmark.ts --preset expert --project all --model claude-sonnet-4-6`);
  lines.push(``);
  lines.push(`# Generate leaderboard`);
  lines.push(`npx tsx _scoring/leaderboard.ts --format md --out LEADERBOARD.md`);
  lines.push("```");
  lines.push(``);
  lines.push(`---`);
  lines.push(`*Generated by [TRASHFIRE](https://github.com/YOUR_USER/trashfire) benchmark suite*`);

  return lines.join("\n");
}

// ─── JSON Leaderboard ────────────────────────────────────────────────────────

function generateJSON(entries: IndexEntry[]): string {
  return JSON.stringify({
    leaderboard: {
      generated_at: new Date().toISOString(),
      total_runs: entries.length,
      total_models: new Set(entries.map(e => e.model)).size,
      entries: entries.map((e, i) => ({
        rank: i + 1,
        ...e,
        composite_score_pct: pct(e.composite_score),
      })),
    },
  }, null, 2);
}

// ─── HTML Leaderboard ────────────────────────────────────────────────────────

function generateHTML(entries: IndexEntry[]): string {
  const best = entries[0];
  const rows = entries.map((e, i) => `
      <tr class="${i < 3 ? 'top-3' : ''}">
        <td class="rank">${medal(i)}</td>
        <td><strong>${e.model_display}</strong><br><small class="provider">${e.provider}</small></td>
        <td>${e.preset}</td>
        <td>${skillLabel(e)}</td>
        <td class="score"><strong>${pct(e.composite_score)}</strong></td>
        <td>${pct(e.recall)}</td>
        <td>${pct(e.precision)}</td>
        <td>${e.false_positives}</td>
        <td>${e.projects_tested}</td>
        <td class="date">${e.timestamp.split("T")[0]}</td>
      </tr>`).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TRASHFIRE Leaderboard  - AI Code Review Benchmark</title>
  <meta name="description" content="Benchmark leaderboard for AI code review tools across 42 projects, 4200+ planted issues, 30+ languages">
  <meta property="og:title" content="TRASHFIRE  - AI Code Review Benchmark">
  <meta property="og:description" content="How well can AI find bugs? ${entries.length} runs, ${new Set(entries.map(e => e.model)).size} models. Current leader: ${best?.model_display} at ${best ? pct(best.composite_score) : 'N/A'}">
  <style>
    :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #f97316; --green: #3fb950; --red: #f85149; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
    h1 span { color: var(--accent); }
    .subtitle { color: var(--muted); font-size: 1.1rem; margin-bottom: 2rem; }
    .stats { display: flex; gap: 2rem; margin-bottom: 2rem; flex-wrap: wrap; }
    .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; min-width: 180px; }
    .stat-value { font-size: 2rem; font-weight: 700; color: var(--accent); }
    .stat-label { color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; }
    th { background: #1c2333; padding: 1rem; text-align: left; font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    td { padding: 0.875rem 1rem; border-top: 1px solid var(--border); }
    .rank { font-size: 1.25rem; text-align: center; width: 60px; }
    .score { font-size: 1.1rem; color: var(--green); }
    .top-3 { background: rgba(249, 115, 22, 0.05); }
    .provider { color: var(--muted); }
    .date { color: var(--muted); font-size: 0.85rem; }
    .methodology { margin-top: 3rem; padding: 2rem; background: var(--surface); border-radius: 12px; border: 1px solid var(--border); }
    .methodology h2 { margin-bottom: 1rem; }
    .methodology ul { padding-left: 1.5rem; color: var(--muted); line-height: 1.8; }
    footer { margin-top: 3rem; text-align: center; color: var(--muted); font-size: 0.85rem; }
    footer a { color: var(--accent); text-decoration: none; }
    @media (max-width: 768px) { body { padding: 1rem; } .stats { flex-direction: column; } table { font-size: 0.85rem; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔥 <span>TRASHFIRE</span> Leaderboard</h1>
    <p class="subtitle">AI Code Review Benchmark  - ${entries.length} runs across ${new Set(entries.map(e => e.model)).size} models • Last updated: ${new Date().toISOString().split("T")[0]}</p>

    <div class="stats">
      <div class="stat"><div class="stat-value">${best ? pct(best.composite_score) : ' -'}</div><div class="stat-label">Best Score (${best?.model_display ?? ' -'})</div></div>
      <div class="stat"><div class="stat-value">42</div><div class="stat-label">Projects / 30+ Languages</div></div>
      <div class="stat"><div class="stat-value">4,200+</div><div class="stat-label">Planted Issues</div></div>
      <div class="stat"><div class="stat-value">${entries.length}</div><div class="stat-label">Benchmark Runs</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Rank</th><th>Model</th><th>Prompt</th><th>Skills</th><th>Score</th><th>Recall</th><th>Precision</th><th>FP</th><th>Projects</th><th>Date</th>
        </tr>
      </thead>
      <tbody>${rows}
      </tbody>
    </table>

    <div class="methodology">
      <h2>Methodology</h2>
      <ul>
        <li><strong>42 vulnerable projects</strong> across 30+ languages/frameworks (Next.js, Flask, Go, Rust, Solidity, Haskell, Zig, ...)</li>
        <li><strong>~4,200 planted issues:</strong> Security (35%), Tricky cross-module (25%), Logic (20%), Performance (10%), Best Practices (5%), Code Smells (5%)</li>
        <li><strong>~300 red herrings:</strong> Code that looks vulnerable but is safe (tests false-positive rate)</li>
        <li><strong>Difficulty tiers 1-5</strong> with multipliers ×1.0 to ×3.0 (finding hard bugs scores more)</li>
        <li><strong>Encrypted ground truth</strong> (AES-256-GCM)  - unavailable to reviewers during testing</li>
        <li><strong>Blind testing:</strong> All bug markers stripped from source code</li>
      </ul>
    </div>

    <footer>
      Generated by <a href="https://github.com/YOUR_USER/trashfire">TRASHFIRE</a> benchmark suite
    </footer>
  </div>
</body>
</html>`;
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  const format = args[args.indexOf("--format") + 1] || "md";
  const outIdx = args.indexOf("--out");

  const entries = loadIndex();

  if (entries.length === 0) {
    console.log("No benchmark results found. Run some benchmarks first!");
    console.log("  npx tsx benchmark.ts --preset vanilla --project grog-shop");
    process.exit(0);
  }

  let output: string;
  let defaultFile: string;

  switch (format) {
    case "json":
      output = generateJSON(entries);
      defaultFile = "LEADERBOARD.json";
      break;
    case "html":
      output = generateHTML(entries);
      defaultFile = "LEADERBOARD.html";
      break;
    default:
      output = generateMarkdown(entries);
      defaultFile = "LEADERBOARD.md";
  }

  const outPath = outIdx !== -1 ? args[outIdx + 1] : join(ROOT, defaultFile);
  writeFileSync(outPath, output);
  console.log(`Leaderboard written to ${outPath} (${entries.length} entries)`);
}

main();
