import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { decryptManifest } from "./crypto.js";
import type {
  ProjectManifest,
  ReviewerOutput,
  ReviewerFinding,
  Issue,
  IssueCategory,
  IssueSeverity,
  DifficultyTier,
  IssueScore,
  CategoryScore,
  ProjectScoreReport,
  BenchmarkReport,
} from "./types.js";
import { DIFFICULTY_MULTIPLIERS, CATEGORY_WEIGHTS } from "./types.js";

// ─── Severity Normalization ──────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, IssueSeverity> = {
  critical: "CRITICAL",
  crit: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  med: "MEDIUM",
  moderate: "MEDIUM",
  low: "LOW",
  info: "LOW",
  informational: "LOW",
};

function normalizeSeverity(raw: string): IssueSeverity | null {
  const key = raw.trim().toLowerCase();
  return SEVERITY_MAP[key] ?? null;
}

// ─── Category Normalization ──────────────────────────────────────────────────

const CATEGORY_MAP: Record<string, IssueCategory> = {
  // Security
  security: "SEC",
  sec: "SEC",
  vulnerability: "SEC",
  vuln: "SEC",
  injection: "SEC",
  auth: "SEC",
  authentication: "SEC",
  authorization: "SEC",
  crypto: "SEC",
  cryptography: "SEC",
  // Logic
  logic: "LOGIC",
  bug: "LOGIC",
  "logic bug": "LOGIC",
  "logic error": "LOGIC",
  correctness: "LOGIC",
  // Performance
  performance: "PERF",
  perf: "PERF",
  "performance issue": "PERF",
  // Best Practice
  "best practice": "BP",
  "best-practice": "BP",
  bp: "BP",
  practice: "BP",
  "best practices": "BP",
  hardening: "BP",
  configuration: "BP",
  config: "BP",
  // Code Smell
  smell: "SMELL",
  "code smell": "SMELL",
  "code-smell": "SMELL",
  maintainability: "SMELL",
  quality: "SMELL",
  "code quality": "SMELL",
  // Tricky / Cross-Module
  tricky: "TRICKY",
  "cross-module": "TRICKY",
  "cross-cutting": "TRICKY",
  subtle: "TRICKY",
  "race condition": "TRICKY",
  race: "TRICKY",
  toctou: "TRICKY",
  "cross-file": "TRICKY",
};

function normalizeCategory(raw: string): IssueCategory | null {
  const key = raw.trim().toLowerCase();
  return CATEGORY_MAP[key] ?? null;
}

// ─── Severity Distance ───────────────────────────────────────────────────────

const SEVERITY_ORDER: IssueSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function severityDistance(a: IssueSeverity, b: IssueSeverity): number {
  return Math.abs(SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b));
}

// ─── CWE Matching ────────────────────────────────────────────────────────────

function normalizeCWE(raw: string | undefined): string | null {
  if (!raw) return null;
  const match = raw.match(/CWE-?(\d+)/i);
  return match ? `CWE-${match[1]}` : null;
}

// ─── File Path Matching ──────────────────────────────────────────────────────

function pathsMatch(issuePath: string, findingPath: string): boolean {
  // Normalize paths - handle various formats reviewers use:
  // Manifest: "grog-shop/lib/auth.ts"
  // Reviewer: "lib/auth.ts", "grog-shop/lib/auth.ts", "./lib/auth.ts",
  //           "vaults/grog-shop/lib/auth.ts", "_blind/grog-shop/lib/auth.ts"
  const normalize = (p: string) =>
    p.replace(/^\.\//, "").replace(/^(_blind|vaults)\//, "").toLowerCase();

  const a = normalize(issuePath);
  const b = normalize(findingPath);

  if (a === b) return true;
  if (a.endsWith(b) || b.endsWith(a)) return true;
  // Strip project prefix from both and compare
  const stripFirst = (s: string) => s.replace(/^[^/]+\//, "");
  if (stripFirst(a) === stripFirst(b)) return true;
  if (stripFirst(a) === b || a === stripFirst(b)) return true;
  return false;
}

// ─── Line Proximity ──────────────────────────────────────────────────────────

function lineProximity(issueLine: number, findingLine: number): number {
  const dist = Math.abs(issueLine - findingLine);
  if (dist === 0) return 1.0;
  if (dist <= 5) return 0.75;
  if (dist <= 10) return 0.5;
  return 0;
}

// ─── Text Similarity (simple keyword overlap) ────────────────────────────────

function textSimilarity(a: string, b: string): number {
  const tokenize = (s: string) =>
    new Set(
      s
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter((w) => w.length > 2)
    );

  const tokensA = tokenize(a);
  const tokensB = tokenize(b);
  if (tokensA.size === 0 || tokensB.size === 0) return 0;

  let overlap = 0;
  for (const t of tokensA) {
    if (tokensB.has(t)) overlap++;
  }

  return (2 * overlap) / (tokensA.size + tokensB.size);
}

// ─── Matching: Reviewer Findings ↔ Ground Truth Issues ───────────────────────

interface Match {
  issueIndex: number;
  findingIndex: number;
  confidence: number;
}

function matchFindings(
  issues: Issue[],
  findings: ReviewerFinding[]
): { matches: Match[]; unmatchedFindings: number[] } {
  const candidates: Match[] = [];

  for (let fi = 0; fi < findings.length; fi++) {
    const f = findings[fi];
    for (let ii = 0; ii < issues.length; ii++) {
      const issue = issues[ii];

      // Check file match
      const fileMatch = issue.files.some((loc) => pathsMatch(loc.path, f.file));
      if (!fileMatch) continue;

      // Check line proximity
      const bestLineProx = Math.max(
        ...issue.files
          .filter((loc) => pathsMatch(loc.path, f.file))
          .map((loc) => lineProximity(loc.line_start, f.line))
      );

      // Text similarity on title + description
      const titleSim = textSimilarity(issue.title, f.title);
      const descSim = textSimilarity(issue.description, f.description);
      const textScore = Math.max(titleSim, descSim);

      // Need file match AND (line proximity OR text similarity)
      if (bestLineProx === 0 && textScore < 0.3) continue;

      const confidence = bestLineProx * 0.4 + textScore * 0.6;
      candidates.push({ issueIndex: ii, findingIndex: fi, confidence });
    }
  }

  // Greedy matching: highest confidence first, no double-assignment
  candidates.sort((a, b) => b.confidence - a.confidence);
  const matchedIssues = new Set<number>();
  const matchedFindings = new Set<number>();
  const matches: Match[] = [];

  for (const c of candidates) {
    if (matchedIssues.has(c.issueIndex) || matchedFindings.has(c.findingIndex)) continue;
    matches.push(c);
    matchedIssues.add(c.issueIndex);
    matchedFindings.add(c.findingIndex);
  }

  const unmatchedFindings = findings
    .map((_, i) => i)
    .filter((i) => !matchedFindings.has(i));

  return { matches, unmatchedFindings };
}

// ─── Score a Single Issue ────────────────────────────────────────────────────

function scoreIssue(issue: Issue, finding: ReviewerFinding | null): IssueScore {
  if (!finding) {
    return {
      issue_id: issue.id,
      matched: false,
      finding_index: null,
      detection: 0,
      severity_score: 0,
      cwe_score: 0,
      location_score: 0,
      fix_score: 0,
      explanation_score: 0,
      raw_score: 0,
      difficulty_multiplier: DIFFICULTY_MULTIPLIERS[issue.difficulty_tier],
      weighted_score: 0,
    };
  }

  // Detection: 1.0
  const detection = 1.0;

  // Severity: 0.5 (exact), 0.25 (one off), 0 (more)
  const normalizedSev = normalizeSeverity(finding.severity);
  let severity_score = 0;
  if (normalizedSev) {
    const dist = severityDistance(issue.severity, normalizedSev);
    if (dist === 0) severity_score = 0.5;
    else if (dist === 1) severity_score = 0.25;
  }

  // CWE: 0.5 (exact), 0.25 (same OWASP family heuristic), 0
  const normalizedCWE = normalizeCWE(finding.cwe);
  let cwe_score = 0;
  if (normalizedCWE && normalizedCWE === issue.cwe_id) {
    cwe_score = 0.5;
  } else if (normalizedCWE && issue.cwe_id) {
    // Partial: same CWE prefix cluster (rough heuristic)
    const issueCweNum = parseInt(issue.cwe_id.replace("CWE-", ""));
    const findingCweNum = parseInt(normalizedCWE.replace("CWE-", ""));
    if (Math.abs(issueCweNum - findingCweNum) <= 5) cwe_score = 0.25;
  }

  // Location: 0.5 (file + line within 5), 0.25 (file only)
  let location_score = 0;
  for (const loc of issue.files) {
    if (pathsMatch(loc.path, finding.file)) {
      const prox = lineProximity(loc.line_start, finding.line);
      if (prox >= 0.75) {
        location_score = 0.5;
        break;
      } else {
        location_score = Math.max(location_score, 0.25);
      }
    }
  }

  // Fix: 1.0 if provided (we can't verify correctness automatically, so presence = 1.0)
  const fix_score = finding.fix && finding.fix.trim().length > 20 ? 1.0 : 0;

  // Explanation: 0.5 if description is substantive
  const explanation_score = finding.description && finding.description.trim().length > 50 ? 0.5 : 0;

  const raw_score = detection + severity_score + cwe_score + location_score + fix_score + explanation_score;
  const multiplier = DIFFICULTY_MULTIPLIERS[issue.difficulty_tier];

  return {
    issue_id: issue.id,
    matched: true,
    finding_index: null, // set by caller
    detection,
    severity_score,
    cwe_score,
    location_score,
    fix_score,
    explanation_score,
    raw_score,
    difficulty_multiplier: multiplier,
    weighted_score: raw_score * multiplier,
  };
}

// ─── Check Red Herrings ──────────────────────────────────────────────────────

function countRedHerringsFlagged(
  manifest: ProjectManifest,
  findings: ReviewerFinding[],
  unmatchedFindingIndices: number[]
): number {
  let count = 0;
  for (const fi of unmatchedFindingIndices) {
    const f = findings[fi];
    for (const rh of manifest.red_herrings) {
      const fileMatch = rh.files.some((loc) => pathsMatch(loc.path, f.file));
      if (!fileMatch) continue;
      const textScore = textSimilarity(rh.title + " " + rh.description, f.title + " " + f.description);
      if (textScore >= 0.25) {
        count++;
        break;
      }
    }
  }
  return count;
}

// ─── Score a Project ─────────────────────────────────────────────────────────

export function scoreProject(manifest: ProjectManifest, review: ReviewerOutput): ProjectScoreReport {
  const { matches, unmatchedFindings } = matchFindings(manifest.issues, review.findings);

  // Score each issue
  const issueScores: IssueScore[] = manifest.issues.map((issue) => {
    const match = matches.find((m) => manifest.issues[m.issueIndex] === issue);
    if (!match) return scoreIssue(issue, null);

    const finding = review.findings[match.findingIndex];
    const score = scoreIssue(issue, finding);
    score.finding_index = match.findingIndex;
    return score;
  });

  // Red herrings
  const rhFlagged = countRedHerringsFlagged(manifest, review.findings, unmatchedFindings);
  const pureFalsePositives = unmatchedFindings.length - rhFlagged;

  // Category scores
  const categories: IssueCategory[] = ["SEC", "LOGIC", "PERF", "BP", "SMELL", "TRICKY"];
  const byCategory = {} as Record<IssueCategory, CategoryScore>;

  for (const cat of categories) {
    const catIssues = manifest.issues.filter((i) => i.category === cat);
    const catScores = issueScores.filter((s) => {
      const issue = manifest.issues.find((i) => i.id === s.issue_id);
      return issue?.category === cat;
    });

    const tp = catScores.filter((s) => s.matched).length;
    const fn = catScores.filter((s) => !s.matched).length;

    // FP attributed to this category (from unmatched findings that claim this category)
    const fp = unmatchedFindings.filter((fi) => {
      const normCat = normalizeCategory(review.findings[fi].category);
      return normCat === cat;
    }).length;

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    const weightedScore = catScores.reduce((sum, s) => sum + s.weighted_score, 0);
    const maxPossible = catIssues.reduce(
      (sum, i) => sum + 4.0 * DIFFICULTY_MULTIPLIERS[i.difficulty_tier],
      0
    );
    const normalizedScore = maxPossible > 0 ? weightedScore / maxPossible : 0;

    byCategory[cat] = { category: cat, true_positives: tp, false_negatives: fn, false_positives: fp, precision, recall, f1, weighted_score: weightedScore, max_possible: maxPossible, normalized_score: normalizedScore };
  }

  // Difficulty tier breakdown
  const tiers: DifficultyTier[] = [1, 2, 3, 4, 5];
  const byDifficultyTier = {} as Record<DifficultyTier, { recall: number; count: number; matched: number }>;
  for (const tier of tiers) {
    const tierIssues = manifest.issues.filter((i) => i.difficulty_tier === tier);
    const tierMatched = issueScores.filter((s) => {
      const issue = manifest.issues.find((i) => i.id === s.issue_id);
      return issue?.difficulty_tier === tier && s.matched;
    }).length;
    byDifficultyTier[tier] = {
      count: tierIssues.length,
      matched: tierMatched,
      recall: tierIssues.length > 0 ? tierMatched / tierIssues.length : 0,
    };
  }

  // Composite score — severity-weighted, category-independent
  // CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2
  const SEVERITY_POINTS: Record<IssueSeverity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2 };

  const maxPossiblePoints = manifest.issues.reduce(
    (sum, i) => sum + SEVERITY_POINTS[i.severity],
    0
  );

  const earnedPoints = manifest.issues.reduce((sum, issue, idx) => {
    const score = issueScores[idx];
    return sum + (score.matched ? SEVERITY_POINTS[issue.severity] : 0);
  }, 0);

  // FP penalty: -1 per false positive, -2 per flagged red herring
  const fpPenaltyPoints = pureFalsePositives * 1 + rhFlagged * 2;
  const fpPenalty = maxPossiblePoints > 0 ? fpPenaltyPoints / maxPossiblePoints : 0;

  const compositeScore = maxPossiblePoints > 0
    ? Math.max(0, (earnedPoints - fpPenaltyPoints) / maxPossiblePoints)
    : 0;

  return {
    project: manifest.project,
    reviewer: review.reviewer,
    timestamp: review.timestamp,
    total_issues: manifest.total_issues,
    total_red_herrings: manifest.total_red_herrings,
    matched_issues: matches.length,
    missed_issues: manifest.total_issues - matches.length,
    false_positives: pureFalsePositives,
    red_herrings_flagged: rhFlagged,
    false_positive_penalty: fpPenalty,
    by_category: byCategory,
    by_difficulty_tier: byDifficultyTier,
    composite_score: compositeScore,
    issue_scores: issueScores,
  };
}

// ─── Aggregate Benchmark Report ──────────────────────────────────────────────

export function aggregateReport(projects: ProjectScoreReport[], reviewer: string): BenchmarkReport {
  const scores = projects.map((p) => p.composite_score);
  const sorted = [...scores].sort((a, b) => a - b);
  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const median =
    sorted.length % 2 === 0
      ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
      : sorted[Math.floor(sorted.length / 2)];

  const worst = projects.reduce((w, p) => (p.composite_score < w.composite_score ? p : w));
  const best = projects.reduce((b, p) => (p.composite_score > b.composite_score ? p : b));

  const totalTP = projects.reduce((s, p) => s + p.matched_issues, 0);
  const totalFP = projects.reduce((s, p) => s + p.false_positives, 0);
  const totalFN = projects.reduce((s, p) => s + p.missed_issues, 0);
  const totalRH = projects.reduce((s, p) => s + p.red_herrings_flagged, 0);

  const categories: IssueCategory[] = ["SEC", "LOGIC", "PERF", "BP", "SMELL", "TRICKY"];
  const byCategory = {} as Record<IssueCategory, { precision: number; recall: number; f1: number; weighted_score: number }>;

  for (const cat of categories) {
    const tp = projects.reduce((s, p) => s + p.by_category[cat].true_positives, 0);
    const fp = projects.reduce((s, p) => s + p.by_category[cat].false_positives, 0);
    const fn = projects.reduce((s, p) => s + p.by_category[cat].false_negatives, 0);
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const ws = projects.reduce((s, p) => s + p.by_category[cat].normalized_score, 0) / projects.length;
    byCategory[cat] = { precision, recall, f1, weighted_score: ws };
  }

  const tiers: DifficultyTier[] = [1, 2, 3, 4, 5];
  const byDifficultyTier = {} as Record<DifficultyTier, { recall: number }>;
  for (const tier of tiers) {
    const totalCount = projects.reduce((s, p) => s + p.by_difficulty_tier[tier].count, 0);
    const totalMatched = projects.reduce((s, p) => s + p.by_difficulty_tier[tier].matched, 0);
    byDifficultyTier[tier] = { recall: totalCount > 0 ? totalMatched / totalCount : 0 };
  }

  return {
    reviewer,
    benchmark_version: "1.0.0",
    run_timestamp: new Date().toISOString(),
    aggregate: {
      mean_score: mean,
      median_score: median,
      worst_project: { project: worst.project, score: worst.composite_score },
      best_project: { project: best.project, score: best.composite_score },
      total_tp: totalTP,
      total_fp: totalFP,
      total_fn: totalFN,
      total_rh_flagged: totalRH,
      overall_precision: totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 0,
      overall_recall: totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 0,
    },
    by_category: byCategory,
    by_difficulty_tier: byDifficultyTier,
    projects,
  };
}

// ─── Human-Readable Summary ──────────────────────────────────────────────────

function formatPercent(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

export function formatProjectReport(report: ProjectScoreReport): string {
  const lines: string[] = [];
  lines.push(`# Score Report: ${report.project}`);
  lines.push(`Reviewer: ${report.reviewer} | ${report.timestamp}`);
  lines.push("");
  lines.push(`## Composite Score: ${formatPercent(report.composite_score)}`);
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Issues Found | ${report.matched_issues} / ${report.total_issues} |`);
  lines.push(`| Missed | ${report.missed_issues} |`);
  lines.push(`| False Positives | ${report.false_positives} |`);
  lines.push(`| Red Herrings Flagged | ${report.red_herrings_flagged} / ${report.total_red_herrings} |`);
  lines.push(`| FP Penalty | ${formatPercent(report.false_positive_penalty)} |`);
  lines.push("");
  lines.push(`## By Category`);
  lines.push("");
  lines.push(`| Category | Precision | Recall | F1 | Score |`);
  lines.push(`|----------|-----------|--------|-----|-------|`);
  for (const cat of ["SEC", "LOGIC", "PERF", "BP", "SMELL", "TRICKY"] as IssueCategory[]) {
    const c = report.by_category[cat];
    lines.push(
      `| ${cat} | ${formatPercent(c.precision)} | ${formatPercent(c.recall)} | ${formatPercent(c.f1)} | ${formatPercent(c.normalized_score)} |`
    );
  }
  lines.push("");
  lines.push(`## By Difficulty Tier`);
  lines.push("");
  lines.push(`| Tier | Found | Total | Recall |`);
  lines.push(`|------|-------|-------|--------|`);
  for (const tier of [1, 2, 3, 4, 5] as DifficultyTier[]) {
    const t = report.by_difficulty_tier[tier];
    lines.push(`| ${tier} | ${t.matched} | ${t.count} | ${formatPercent(t.recall)} |`);
  }

  return lines.join("\n");
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

async function promptPassphrase(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question("Passphrase: ", (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const manifestIndex = args.indexOf("--manifest");
  const reviewIndex = args.indexOf("--review");
  const outputIndex = args.indexOf("--output");

  if (manifestIndex === -1 || reviewIndex === -1) {
    console.error("Usage: npx tsx score.ts --manifest <project.enc> --review <review.json> [--output <report.md>]");
    process.exit(1);
  }

  const manifestPath = args[manifestIndex + 1];
  const reviewPath = args[reviewIndex + 1];

  // Determine if encrypted or plain JSON
  const isEncrypted = manifestPath.endsWith(".enc");

  let manifestJson: string;
  if (isEncrypted) {
    const passphrase = await promptPassphrase();
    manifestJson = decryptManifest(manifestPath, passphrase);
  } else {
    manifestJson = readFileSync(manifestPath, "utf-8");
  }

  const manifest: ProjectManifest = JSON.parse(manifestJson);
  const review: ReviewerOutput = JSON.parse(readFileSync(reviewPath, "utf-8"));

  const report = scoreProject(manifest, review);
  const formatted = formatProjectReport(report);

  // Output
  if (outputIndex !== -1) {
    const { writeFileSync: wfs } = await import("node:fs");
    wfs(args[outputIndex + 1], formatted);
    // Also write JSON report
    wfs(args[outputIndex + 1].replace(/\.md$/, ".json"), JSON.stringify(report, null, 2));
    console.error(`Report written to ${args[outputIndex + 1]}`);
  } else {
    console.log(formatted);
  }

  // Also print JSON to stderr for piping
  console.error(JSON.stringify({ composite_score: report.composite_score }, null, 2));
}

const isDirectRun = process.argv[1]?.endsWith("score.ts");
if (isDirectRun) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}
