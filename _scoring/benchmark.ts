#!/usr/bin/env npx tsx
/**
 * benchmark.ts  - Standardized benchmark runner for TRASHFIRE
 *
 * Runs a code review benchmark with configurable model, prompt, skills,
 * and produces structured JSON results with full reproducibility metadata.
 *
 * Usage:
 *   npx tsx benchmark.ts --config run-config.json
 *   npx tsx benchmark.ts --model claude-opus-4-20250514 --prompt "Review for security issues" --project grog-shop
 *   npx tsx benchmark.ts --preset vanilla --project grog-shop
 *   npx tsx benchmark.ts --preset superpowers --project all --model claude-sonnet-4-20250514
 *
 * Presets: vanilla, security, thorough, superpowers, supaskills-single, supaskills-multi
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { join, basename } from "node:path";
import { execSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

interface BenchmarkConfig {
  run_id: string;
  model: string;
  provider: string; // "anthropic", "openai", "google", "local"
  prompt_preset: string;
  prompt_text: string;
  prompt_file?: string;
  skills: string[];
  skill_source?: string; // "supaskills", "superpowers", "custom"
  projects: string[]; // project names or ["all"]
  passphrase: string;
  blind_dir: string;
  manifest_dir: string;
  output_dir: string;
  tags: string[];
  notes: string;
  // Advanced
  max_tokens?: number;
  temperature?: number;
  num_passes?: number; // multi-pass review
}

interface BenchmarkResult {
  // Metadata (for reproducibility)
  meta: {
    run_id: string;
    timestamp: string;
    duration_ms: number;
    trashfire_version: string;
    model: string;
    model_display: string;
    provider: string;
    prompt_preset: string;
    prompt_text: string;
    prompt_hash: string; // SHA-256 of prompt for dedup
    skills: string[];
    skill_source: string;
    tags: string[];
    notes: string;
    num_passes: number;
    host: string;
    cli_version: string;
  };
  // Per-project scores
  projects: ProjectResult[];
  // Aggregate
  aggregate: {
    composite_score: number;
    mean_score: number;
    median_score: number;
    min_score: number;
    max_score: number;
    total_issues: number;
    total_found: number;
    total_missed: number;
    total_false_positives: number;
    total_red_herrings_flagged: number;
    overall_recall: number;
    overall_precision: number;
    by_category: Record<string, { recall: number; precision: number; f1: number; score: number }>;
    by_difficulty: Record<string, { recall: number }>;
  };
}

interface ProjectResult {
  project: string;
  composite_score: number;
  issues_found: number;
  issues_total: number;
  false_positives: number;
  red_herrings_flagged: number;
  recall: number;
  precision: number;
  duration_ms: number;
  findings_count: number;
  by_category: Record<string, { recall: number; precision: number; f1: number; score: number }>;
  by_difficulty: Record<string, { recall: number; count: number; matched: number }>;
}

// ─── Prompt Presets ──────────────────────────────────────────────────────────

const PRESETS: Record<string, { name: string; prompt: string; skills: string[]; skill_source: string }> = {
  vanilla: {
    name: "Vanilla (no guidance)",
    prompt: "Review this codebase for any issues you can find. Check all the files.",
    skills: [],
    skill_source: "none",
  },
  security: {
    name: "Security Focus",
    prompt: `You are an security security reviewer. Review this codebase for security vulnerabilities.
Check every file thoroughly for: SQL injection, XSS, auth bypass, RCE, SSRF, IDOR, CSRF, path traversal,
command injection, deserialization, hardcoded secrets, weak crypto, and any other security issues.
For each finding provide: file, line, severity, CWE, title, description, and fix.`,
    skills: [],
    skill_source: "none",
  },
  "thorough": {
    name: "Experienced Developer",
    prompt: `Review all files in this codebase as an experienced senior developer.
Find: security bugs (SQLi, XSS, auth issues, injection, SSRF, IDOR), logic errors (race conditions,
off-by-one, wrong comparisons, missing null checks, async problems), performance problems (N+1 queries,
memory leaks, blocking calls), bad practices (hardcoded values, swallowed errors, missing validation,
weak crypto), and tricky cross-function bugs.
Think about edge cases: empty arrays, negative numbers, Unicode, concurrent requests, float arithmetic
for money, TOCTOU problems, missing permission checks.`,
    skills: [],
    skill_source: "none",
  },
  superpowers: {
    name: "Superpowers (obra/superpowers)",
    prompt: `Review this codebase using systematic security analysis. For each file:
1. Map all data flows from untrusted inputs to sensitive operations
2. Check every authentication and authorization boundary
3. Identify all cryptographic operations and validate their correctness
4. Find race conditions, TOCTOU, and concurrency issues
5. Check for injection vectors (SQL, command, template, deserialization)
6. Verify error handling doesn't leak sensitive information
7. Check configuration for security misconfigurations
8. Look for logic bugs that could be exploited
9. Identify performance anti-patterns and resource exhaustion vectors
10. Find cross-module bugs where individually-safe functions become dangerous when composed`,
    skills: [],
    skill_source: "superpowers",
  },
  "supaskills-single": {
    name: "SupaSkills (single security skill)",
    prompt: "Review this codebase for security vulnerabilities. Check every file.",
    skills: ["security-code-reviewer"],
    skill_source: "supaskills",
  },
  "supaskills-multi": {
    name: "SupaSkills (multi-skill)",
    prompt: "Review this codebase for all types of issues - security, performance, code quality, and best practices.",
    skills: ["security-code-reviewer", "performance-analyzer", "code-quality-reviewer"],
    skill_source: "supaskills",
  },
  custom: {
    name: "Custom Prompt",
    prompt: "", // will be filled from --prompt flag
    skills: [],
    skill_source: "none",
  },
};

// ─── Model Display Names ─────────────────────────────────────────────────────

const MODEL_DISPLAY: Record<string, string> = {
  "claude-opus-4-20250514": "Claude Opus 4",
  "claude-opus-4-6": "Claude Opus 4.6",
  "claude-sonnet-4-20250514": "Claude Sonnet 4",
  "claude-sonnet-4-6": "Claude Sonnet 4.6",
  "claude-haiku-4-5-20251001": "Claude Haiku 4.5",
  "gpt-4o": "GPT-4o",
  "gpt-4o-mini": "GPT-4o Mini",
  "o3": "o3",
  "o4-mini": "o4-mini",
  "gemini-2.5-pro": "Gemini 2.5 Pro",
  "gemini-2.5-flash": "Gemini 2.5 Flash",
  "deepseek-r1": "DeepSeek R1",
  "llama-4-maverick": "Llama 4 Maverick",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getProjectList(rootDir: string): string[] {
  return readdirSync(rootDir, { withFileTypes: true })
    .filter(e => e.isDirectory() && !e.name.startsWith("_") && !e.name.startsWith(".") && e.name !== "node_modules")
    .map(e => e.name)
    .sort();
}

function hashString(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 12);
}

function getHostInfo(): string {
  try {
    return execSync("hostname", { encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

function getCLIVersion(): string {
  try {
    return execSync("claude --version 2>/dev/null || echo unknown", { encoding: "utf-8" }).trim();
  } catch {
    return "unknown";
  }
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

// ─── Review Runner ───────────────────────────────────────────────────────────

function buildReviewPrompt(config: BenchmarkConfig, project: string): string {
  const projectDir = join(config.blind_dir, project);
  return `${config.prompt_text}

After reviewing ALL files in ${projectDir}, output your complete findings as JSON:
{
  "reviewer": "${config.model}",
  "project": "${project}",
  "timestamp": "${new Date().toISOString()}",
  "findings": [
    {
      "file": "${project}/path/to/file",
      "line": 42,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "security|logic|performance|best-practice|tricky",
      "cwe": "CWE-89",
      "title": "Short description",
      "description": "Detailed explanation",
      "fix": "How to fix"
    }
  ]
}

Write ONLY the JSON to stdout. No other text.`;
}

function runReview(config: BenchmarkConfig, project: string, reviewOutputPath: string): number {
  const startTime = Date.now();
  const prompt = buildReviewPrompt(config, project);
  const projectDir = join(config.blind_dir, project);

  // Build claude command
  const args = [
    "--model", config.model,
    "--output-format", "text",
    "--max-turns", "50",
    "--print",
    "-p", prompt,
  ];

  // Add skills
  for (const skill of config.skills) {
    args.push("--skill", skill);
  }

  console.log(`    Running review with ${config.model}...`);

  try {
    const result = spawnSync("claude", args, {
      cwd: projectDir,
      encoding: "utf-8",
      timeout: 600000, // 10 min per project
      maxBuffer: 10 * 1024 * 1024,
    });

    const output = result.stdout || "";
    const duration = Date.now() - startTime;

    // Try to extract JSON from output
    const jsonMatch = output.match(/\{[\s\S]*"findings"[\s\S]*\}/);
    if (jsonMatch) {
      writeFileSync(reviewOutputPath, jsonMatch[0]);
    } else {
      // Create empty findings file
      const emptyReview = {
        reviewer: config.model,
        project,
        timestamp: new Date().toISOString(),
        findings: [],
      };
      writeFileSync(reviewOutputPath, JSON.stringify(emptyReview, null, 2));
      console.log(`    WARNING: Could not extract JSON from review output`);
    }

    return duration;
  } catch (err: any) {
    console.log(`    ERROR: Review failed: ${err.message}`);
    const emptyReview = {
      reviewer: config.model,
      project,
      timestamp: new Date().toISOString(),
      findings: [],
    };
    writeFileSync(reviewOutputPath, JSON.stringify(emptyReview, null, 2));
    return Date.now() - startTime;
  }
}

// ─── Score a Review ──────────────────────────────────────────────────────────

function scoreReview(manifestPath: string, reviewPath: string, passphrase: string): any {
  const scoringDir = join(import.meta.dirname ?? ".");
  try {
    const result = spawnSync("npx", [
      "tsx", join(scoringDir, "score.ts"),
      "--manifest", manifestPath,
      "--review", reviewPath,
    ], {
      input: passphrase + "\n",
      encoding: "utf-8",
      timeout: 60000,
    });

    // Parse the JSON report from the .json output
    const jsonReportPath = reviewPath.replace(/\.json$/, "-report.json");
    const reportPath = reviewPath.replace(/\.json$/, "-report.md");

    // score.ts writes to --output path, but we didn't pass one, so read stderr
    const stderrJson = result.stderr?.match(/\{[\s\S]*composite_score[\s\S]*\}/);

    // Run again with output flag
    const result2 = spawnSync("npx", [
      "tsx", join(scoringDir, "score.ts"),
      "--manifest", manifestPath,
      "--review", reviewPath,
      "--output", reportPath,
    ], {
      input: passphrase + "\n",
      encoding: "utf-8",
      timeout: 60000,
    });

    // Read the JSON report
    const jsonPath = reportPath.replace(/\.md$/, ".json");
    if (existsSync(jsonPath)) {
      return JSON.parse(readFileSync(jsonPath, "utf-8"));
    }

    return null;
  } catch (err: any) {
    console.log(`    ERROR scoring: ${err.message}`);
    return null;
  }
}

// ─── Main Benchmark ──────────────────────────────────────────────────────────

function runBenchmark(config: BenchmarkConfig): BenchmarkResult {
  const startTime = Date.now();
  const runDir = join(config.output_dir, config.run_id);
  mkdirSync(runDir, { recursive: true });

  // Save config
  writeFileSync(join(runDir, "config.json"), JSON.stringify(config, null, 2));

  const projectResults: ProjectResult[] = [];

  for (let i = 0; i < config.projects.length; i++) {
    const project = config.projects[i];
    console.log(`  [${i + 1}/${config.projects.length}] ${project}`);

    const reviewPath = join(runDir, `${project}-review.json`);
    const manifestPath = join(config.manifest_dir, `${project}.enc`);

    if (!existsSync(manifestPath)) {
      console.log(`    SKIP: No manifest found for ${project}`);
      continue;
    }

    // Run review
    const reviewDuration = runReview(config, project, reviewPath);
    console.log(`    Review completed in ${formatDuration(reviewDuration)}`);

    // Score
    const scoreReport = scoreReview(manifestPath, reviewPath, config.passphrase);

    if (scoreReport) {
      const result: ProjectResult = {
        project,
        composite_score: scoreReport.composite_score,
        issues_found: scoreReport.matched_issues,
        issues_total: scoreReport.total_issues,
        false_positives: scoreReport.false_positives,
        red_herrings_flagged: scoreReport.red_herrings_flagged,
        recall: scoreReport.total_issues > 0 ? scoreReport.matched_issues / scoreReport.total_issues : 0,
        precision: (scoreReport.matched_issues + scoreReport.false_positives) > 0
          ? scoreReport.matched_issues / (scoreReport.matched_issues + scoreReport.false_positives) : 0,
        duration_ms: reviewDuration,
        findings_count: scoreReport.matched_issues + scoreReport.false_positives,
        by_category: Object.fromEntries(
          Object.entries(scoreReport.by_category || {}).map(([k, v]: [string, any]) => [
            k,
            { recall: v.recall, precision: v.precision, f1: v.f1, score: v.normalized_score },
          ])
        ),
        by_difficulty: scoreReport.by_difficulty_tier || {},
      };
      projectResults.push(result);
      console.log(`    Score: ${(result.composite_score * 100).toFixed(1)}% (${result.issues_found}/${result.issues_total} found, ${result.false_positives} FP)`);
    } else {
      console.log(`    FAILED to score`);
    }
  }

  // Aggregate
  const scores = projectResults.map(p => p.composite_score);
  const sorted = [...scores].sort((a, b) => a - b);
  const totalFound = projectResults.reduce((s, p) => s + p.issues_found, 0);
  const totalIssues = projectResults.reduce((s, p) => s + p.issues_total, 0);
  const totalFP = projectResults.reduce((s, p) => s + p.false_positives, 0);
  const totalRH = projectResults.reduce((s, p) => s + p.red_herrings_flagged, 0);

  // Aggregate by_category
  const categories = ["SEC", "LOGIC", "PERF", "BP", "SMELL", "TRICKY"];
  const aggByCategory: Record<string, any> = {};
  for (const cat of categories) {
    const catResults = projectResults.filter(p => p.by_category[cat]);
    if (catResults.length === 0) {
      aggByCategory[cat] = { recall: 0, precision: 0, f1: 0, score: 0 };
      continue;
    }
    const avgRecall = catResults.reduce((s, p) => s + (p.by_category[cat]?.recall || 0), 0) / catResults.length;
    const avgPrecision = catResults.reduce((s, p) => s + (p.by_category[cat]?.precision || 0), 0) / catResults.length;
    const avgF1 = catResults.reduce((s, p) => s + (p.by_category[cat]?.f1 || 0), 0) / catResults.length;
    const avgScore = catResults.reduce((s, p) => s + (p.by_category[cat]?.score || 0), 0) / catResults.length;
    aggByCategory[cat] = { recall: avgRecall, precision: avgPrecision, f1: avgF1, score: avgScore };
  }

  const result: BenchmarkResult = {
    meta: {
      run_id: config.run_id,
      timestamp: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      trashfire_version: "1.0.0",
      model: config.model,
      model_display: MODEL_DISPLAY[config.model] || config.model,
      provider: config.provider,
      prompt_preset: config.prompt_preset,
      prompt_text: config.prompt_text,
      prompt_hash: hashString(config.prompt_text),
      skills: config.skills,
      skill_source: config.skill_source ?? "none",
      tags: config.tags,
      notes: config.notes,
      num_passes: config.num_passes ?? 1,
      host: getHostInfo(),
      cli_version: getCLIVersion(),
    },
    projects: projectResults,
    aggregate: {
      composite_score: scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0,
      mean_score: scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0,
      median_score: sorted.length > 0
        ? sorted.length % 2 === 0
          ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
          : sorted[Math.floor(sorted.length / 2)]
        : 0,
      min_score: sorted[0] ?? 0,
      max_score: sorted[sorted.length - 1] ?? 0,
      total_issues: totalIssues,
      total_found: totalFound,
      total_missed: totalIssues - totalFound,
      total_false_positives: totalFP,
      total_red_herrings_flagged: totalRH,
      overall_recall: totalIssues > 0 ? totalFound / totalIssues : 0,
      overall_precision: (totalFound + totalFP) > 0 ? totalFound / (totalFound + totalFP) : 0,
      by_category: aggByCategory,
      by_difficulty: {},
    },
  };

  // Save result
  const resultPath = join(runDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result, null, 2));

  // Also save to central results index
  appendToResultsIndex(config.output_dir, result);

  console.log(`\n${"═".repeat(60)}`);
  console.log(`  Run: ${config.run_id}`);
  console.log(`  Model: ${result.meta.model_display}`);
  console.log(`  Preset: ${config.prompt_preset}`);
  console.log(`  Projects: ${projectResults.length}`);
  console.log(`  Duration: ${formatDuration(result.meta.duration_ms)}`);
  console.log(`${"─".repeat(60)}`);
  console.log(`  COMPOSITE SCORE: ${(result.aggregate.composite_score * 100).toFixed(1)}%`);
  console.log(`  Recall: ${(result.aggregate.overall_recall * 100).toFixed(1)}% | Precision: ${(result.aggregate.overall_precision * 100).toFixed(1)}%`);
  console.log(`  Found: ${result.aggregate.total_found} / ${result.aggregate.total_issues} | FP: ${result.aggregate.total_false_positives}`);
  console.log(`${"═".repeat(60)}`);
  console.log(`  Results: ${resultPath}`);

  return result;
}

// ─── Results Index ───────────────────────────────────────────────────────────

function appendToResultsIndex(outputDir: string, result: BenchmarkResult): void {
  const indexPath = join(outputDir, "results-index.json");
  let index: any[] = [];
  if (existsSync(indexPath)) {
    try { index = JSON.parse(readFileSync(indexPath, "utf-8")); } catch {}
  }

  index.push({
    run_id: result.meta.run_id,
    timestamp: result.meta.timestamp,
    model: result.meta.model,
    model_display: result.meta.model_display,
    provider: result.meta.provider,
    preset: result.meta.prompt_preset,
    skills: result.meta.skills,
    skill_source: result.meta.skill_source,
    projects_tested: result.projects.length,
    composite_score: result.aggregate.composite_score,
    recall: result.aggregate.overall_recall,
    precision: result.aggregate.overall_precision,
    found: result.aggregate.total_found,
    total: result.aggregate.total_issues,
    false_positives: result.aggregate.total_false_positives,
    duration_ms: result.meta.duration_ms,
    tags: result.meta.tags,
  });

  // Sort by score descending
  index.sort((a: any, b: any) => b.composite_score - a.composite_score);

  writeFileSync(indexPath, JSON.stringify(index, null, 2));
}

// ─── Import Existing Review ──────────────────────────────────────────────────

function importExistingReview(config: BenchmarkConfig, reviewFile: string, project: string): BenchmarkResult {
  // For manually-created review files (like our test runs)
  config.projects = [project];
  const runDir = join(config.output_dir, config.run_id);
  mkdirSync(runDir, { recursive: true });

  // Copy review to run dir
  const reviewPath = join(runDir, `${project}-review.json`);
  writeFileSync(reviewPath, readFileSync(reviewFile, "utf-8"));

  // Score it
  const manifestPath = join(config.manifest_dir, `${project}.enc`);
  const scoreReport = scoreReview(manifestPath, reviewPath, config.passphrase);

  // Build result (simplified)
  const startTime = Date.now();
  const result: BenchmarkResult = {
    meta: {
      run_id: config.run_id,
      timestamp: new Date().toISOString(),
      duration_ms: 0,
      trashfire_version: "1.0.0",
      model: config.model,
      model_display: MODEL_DISPLAY[config.model] || config.model,
      provider: config.provider,
      prompt_preset: config.prompt_preset,
      prompt_text: config.prompt_text,
      prompt_hash: hashString(config.prompt_text),
      skills: config.skills,
      skill_source: config.skill_source ?? "none",
      tags: config.tags,
      notes: config.notes,
      num_passes: 1,
      host: getHostInfo(),
      cli_version: getCLIVersion(),
    },
    projects: scoreReport ? [{
      project,
      composite_score: scoreReport.composite_score,
      issues_found: scoreReport.matched_issues,
      issues_total: scoreReport.total_issues,
      false_positives: scoreReport.false_positives,
      red_herrings_flagged: scoreReport.red_herrings_flagged,
      recall: scoreReport.total_issues > 0 ? scoreReport.matched_issues / scoreReport.total_issues : 0,
      precision: (scoreReport.matched_issues + scoreReport.false_positives) > 0
        ? scoreReport.matched_issues / (scoreReport.matched_issues + scoreReport.false_positives) : 0,
      duration_ms: 0,
      findings_count: scoreReport.matched_issues + scoreReport.false_positives,
      by_category: {},
      by_difficulty: {},
    }] : [],
    aggregate: {
      composite_score: scoreReport?.composite_score ?? 0,
      mean_score: scoreReport?.composite_score ?? 0,
      median_score: scoreReport?.composite_score ?? 0,
      min_score: scoreReport?.composite_score ?? 0,
      max_score: scoreReport?.composite_score ?? 0,
      total_issues: scoreReport?.total_issues ?? 0,
      total_found: scoreReport?.matched_issues ?? 0,
      total_missed: (scoreReport?.total_issues ?? 0) - (scoreReport?.matched_issues ?? 0),
      total_false_positives: scoreReport?.false_positives ?? 0,
      total_red_herrings_flagged: scoreReport?.red_herrings_flagged ?? 0,
      overall_recall: 0,
      overall_precision: 0,
      by_category: {},
      by_difficulty: {},
    },
  };

  const resultPath = join(runDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result, null, 2));
  appendToResultsIndex(config.output_dir, result);

  return result;
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

function parseArgs(): BenchmarkConfig {
  const args = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 ? args[idx + 1] : undefined;
  };
  const has = (flag: string): boolean => args.includes(flag);
  const getAll = (flag: string): string[] => {
    const results: string[] = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === flag && args[i + 1]) results.push(args[i + 1]);
    }
    return results;
  };

  // Load from config file
  if (get("--config")) {
    const configPath = get("--config")!;
    return JSON.parse(readFileSync(configPath, "utf-8"));
  }

  const rootDir = get("--root") ?? join(import.meta.dirname ?? ".", "..");
  const preset = get("--preset") ?? "custom";
  const presetConfig = PRESETS[preset] ?? PRESETS.custom;

  const model = get("--model") ?? "claude-opus-4-6";
  const projectArg = get("--project") ?? "grog-shop";
  const projects = projectArg === "all"
    ? getProjectList(join(rootDir, "_blind"))
    : projectArg.split(",").map(s => s.trim());

  return {
    run_id: `${preset}-${model.split("-").slice(0, 2).join("-")}-${Date.now().toString(36)}`,
    model,
    provider: model.startsWith("claude") ? "anthropic"
      : model.startsWith("gpt") || model.startsWith("o3") || model.startsWith("o4") ? "openai"
      : model.startsWith("gemini") ? "google"
      : "other",
    prompt_preset: preset,
    prompt_text: get("--prompt") ?? presetConfig.prompt,
    skills: getAll("--skill").length > 0 ? getAll("--skill") : presetConfig.skills,
    skill_source: get("--skill-source") ?? presetConfig.skill_source,
    projects,
    passphrase: get("--passphrase") ?? "monkey",
    blind_dir: join(rootDir, "_blind"),
    manifest_dir: join(rootDir, "_manifests"),
    output_dir: join(rootDir, "_results"),
    tags: getAll("--tag"),
    notes: get("--notes") ?? "",
    num_passes: parseInt(get("--passes") ?? "1"),
  };
}

function showHelp(): void {
  console.log(`
TRASHFIRE Benchmark Runner
═══════════════════════════

Usage:
  npx tsx benchmark.ts --preset <name> --project <name|all> [options]

Presets:
  vanilla          No guidance, just "review this code"
  security           Expert security reviewer prompt
  thorough        Experienced developer prompt
  superpowers      obra/superpowers methodology
  supaskills-single  SupaSkills security skill
  supaskills-multi   SupaSkills multi-skill
  custom           Custom prompt via --prompt flag

Options:
  --model <id>       Model to use (default: claude-opus-4-6)
  --project <name>   Project to review, or "all" (default: grog-shop)
  --prompt <text>    Custom prompt text (for preset=custom)
  --skill <name>     Add a skill (can be repeated)
  --passphrase <pw>  Manifest decryption key (default: monkey)
  --tag <tag>        Add a tag (can be repeated)
  --notes <text>     Run notes
  --passes <n>       Number of review passes (default: 1)
  --config <file>    Load config from JSON file
  --import <file>    Import existing review JSON and score it
  --help             Show this help

Examples:
  npx tsx benchmark.ts --preset vanilla --project grog-shop
  npx tsx benchmark.ts --preset security --project all --model claude-sonnet-4-6
  npx tsx benchmark.ts --preset custom --prompt "Find all SQL injections" --project tentacle-labs
  npx tsx benchmark.ts --import review.json --project grog-shop --preset custom --model my-model
`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.length === 0) {
    showHelp();
    process.exit(0);
  }

  const config = parseArgs();
  mkdirSync(config.output_dir, { recursive: true });

  // Import mode
  const importFile = args[args.indexOf("--import") + 1];
  if (args.includes("--import") && importFile) {
    console.log(`Importing review from ${importFile}...`);
    importExistingReview(config, importFile, config.projects[0]);
    process.exit(0);
  }

  console.log(`\nTRASHFIRE Benchmark`);
  console.log(`${"═".repeat(60)}`);
  console.log(`  Model: ${MODEL_DISPLAY[config.model] || config.model}`);
  console.log(`  Preset: ${config.prompt_preset}`);
  console.log(`  Projects: ${config.projects.length}`);
  console.log(`  Skills: ${config.skills.length > 0 ? config.skills.join(", ") : "none"}`);
  console.log(`${"═".repeat(60)}\n`);

  runBenchmark(config);
}

main();
