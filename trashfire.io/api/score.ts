import type { VercelRequest, VercelResponse } from "@vercel/node";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { MANIFESTS, MANIFEST_PROJECTS } from "./_manifests.js";

// ─── Constants ──────────────────────────────────────────────────────────────

const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH = 32;

// ─── Types ──────────────────────────────────────────────────────────────────

type IssueCategory = "SEC" | "LOGIC" | "PERF" | "BP" | "SMELL" | "TRICKY";
type IssueSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type DifficultyTier = 1 | 2 | 3 | 4 | 5;

interface IssueFileLocation {
  path: string;
  line_start: number;
  line_end: number;
  snippet_hash: string;
}

interface Issue {
  id: string;
  project: string;
  category: IssueCategory;
  severity: IssueSeverity;
  difficulty_tier: DifficultyTier;
  cwe_id: string;
  title: string;
  description: string;
  files: IssueFileLocation[];
  tags: string[];
  [key: string]: any;
}

interface RedHerring {
  id: string;
  title: string;
  description: string;
  files: IssueFileLocation[];
  [key: string]: any;
}

interface ProjectManifest {
  project: string;
  total_issues: number;
  total_red_herrings: number;
  issues: Issue[];
  red_herrings: RedHerring[];
  [key: string]: any;
}

interface ReviewerFinding {
  file: string;
  line: number;
  severity: string;
  category: string;
  cwe?: string;
  title: string;
  description: string;
  fix?: string;
}

interface ReviewerOutput {
  reviewer?: string;
  project?: string;
  timestamp?: string;
  findings: ReviewerFinding[];
}

const DIFFICULTY_MULTIPLIERS: Record<DifficultyTier, number> = { 1: 1.0, 2: 1.25, 3: 1.5, 4: 2.0, 5: 3.0 };
const CATEGORY_WEIGHTS: Record<IssueCategory, number> = { SEC: 0.35, LOGIC: 0.20, PERF: 0.10, BP: 0.05, SMELL: 0.05, TRICKY: 0.25 };

// ─── Rate Limiting (in-memory, per Vercel instance) ─────────────────────────

const rateMap = new Map<string, { count: number; reset: number }>();
const RATE_LIMIT = 20; // requests per window
const RATE_WINDOW = 60_000; // 1 minute

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.reset) {
    rateMap.set(ip, { count: 1, reset: now + RATE_WINDOW });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT;
}

// ─── Crypto ─────────────────────────────────────────────────────────────────

function decrypt(data: Buffer, passphrase: string): Buffer {
  let offset = 0;
  const magic = data.subarray(offset, offset + 4);
  if (magic.toString() !== "TFBM") throw new Error("Invalid manifest: bad magic");
  offset += 4;
  offset += 2; // version
  const salt = data.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;
  const iv = data.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const plaintextLength = data.readUInt32BE(offset); offset += 4;
  const tag = data.subarray(offset, offset + TAG_LENGTH); offset += TAG_LENGTH;
  const ciphertext = data.subarray(offset);

  const key = pbkdf2Sync(passphrase, Buffer.from(salt), PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv));
  decipher.setAuthTag(Buffer.from(tag));
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  if (plaintext.length !== plaintextLength) throw new Error("Decryption length mismatch");
  return plaintext;
}

function loadManifest(project: string, passphrase: string): ProjectManifest {
  const b64 = MANIFESTS[project];
  if (!b64) throw new Error(`Unknown project: ${project}`);
  const encData = Buffer.from(b64, "base64");
  const json = decrypt(encData, passphrase).toString("utf-8");
  return JSON.parse(json);
}

// ─── Scoring Logic (ported from _scoring/score.ts) ──────────────────────────

const SEVERITY_MAP: Record<string, IssueSeverity> = {
  critical: "CRITICAL", crit: "CRITICAL", high: "HIGH",
  medium: "MEDIUM", med: "MEDIUM", moderate: "MEDIUM",
  low: "LOW", info: "LOW", informational: "LOW",
};

const CATEGORY_MAP: Record<string, IssueCategory> = {
  security: "SEC", sec: "SEC", vulnerability: "SEC", vuln: "SEC",
  injection: "SEC", auth: "SEC", authentication: "SEC", authorization: "SEC",
  crypto: "SEC", cryptography: "SEC",
  logic: "LOGIC", bug: "LOGIC", "logic bug": "LOGIC", "logic error": "LOGIC", correctness: "LOGIC",
  performance: "PERF", perf: "PERF", "performance issue": "PERF",
  "best practice": "BP", "best-practice": "BP", bp: "BP", practice: "BP",
  "best practices": "BP", hardening: "BP", configuration: "BP", config: "BP",
  smell: "SMELL", "code smell": "SMELL", "code-smell": "SMELL",
  maintainability: "SMELL", quality: "SMELL", "code quality": "SMELL",
  tricky: "TRICKY", "cross-module": "TRICKY", "cross-cutting": "TRICKY",
  subtle: "TRICKY", "race condition": "TRICKY", race: "TRICKY",
  toctou: "TRICKY", "cross-file": "TRICKY",
};

const SEVERITY_ORDER: IssueSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function normalizeSeverity(raw: string): IssueSeverity | null {
  return SEVERITY_MAP[raw.trim().toLowerCase()] ?? null;
}

function normalizeCategory(raw: string): IssueCategory | null {
  return CATEGORY_MAP[raw.trim().toLowerCase()] ?? null;
}

function severityDistance(a: IssueSeverity, b: IssueSeverity): number {
  return Math.abs(SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b));
}

function normalizeCWE(raw: string | undefined): string | null {
  if (!raw) return null;
  const match = raw.match(/CWE-?(\d+)/i);
  return match ? `CWE-${match[1]}` : null;
}

function pathsMatch(issuePath: string, findingPath: string): boolean {
  const normalize = (p: string) => p.replace(/^\.\//, "").replace(/^(_blind|vaults)\//, "").toLowerCase();
  const a = normalize(issuePath);
  const b = normalize(findingPath);
  if (a === b) return true;
  if (a.endsWith(b) || b.endsWith(a)) return true;
  const stripFirst = (s: string) => s.replace(/^[^/]+\//, "");
  if (stripFirst(a) === stripFirst(b)) return true;
  if (stripFirst(a) === b || a === stripFirst(b)) return true;
  return false;
}

function lineProximity(issueLine: number, findingLine: number): number {
  const dist = Math.abs(issueLine - findingLine);
  if (dist === 0) return 1.0;
  if (dist <= 5) return 0.75;
  if (dist <= 10) return 0.5;
  return 0;
}

function textSimilarity(a: string, b: string): number {
  const tokenize = (s: string) => new Set(s.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter(w => w.length > 2));
  const tokensA = tokenize(a);
  const tokensB = tokenize(b);
  if (tokensA.size === 0 || tokensB.size === 0) return 0;
  let overlap = 0;
  for (const t of tokensA) if (tokensB.has(t)) overlap++;
  return (2 * overlap) / (tokensA.size + tokensB.size);
}

interface Match { issueIndex: number; findingIndex: number; confidence: number; }

function matchFindings(issues: Issue[], findings: ReviewerFinding[]): { matches: Match[]; unmatchedFindings: number[] } {
  const candidates: Match[] = [];
  for (let fi = 0; fi < findings.length; fi++) {
    const f = findings[fi];
    for (let ii = 0; ii < issues.length; ii++) {
      const issue = issues[ii];
      const fileMatch = issue.files.some(loc => pathsMatch(loc.path, f.file));
      if (!fileMatch) continue;
      const bestLineProx = Math.max(...issue.files.filter(loc => pathsMatch(loc.path, f.file)).map(loc => lineProximity(loc.line_start, f.line)));
      const titleSim = textSimilarity(issue.title, f.title);
      const descSim = textSimilarity(issue.description, f.description);
      const textScore = Math.max(titleSim, descSim);
      if (bestLineProx === 0 && textScore < 0.3) continue;
      candidates.push({ issueIndex: ii, findingIndex: fi, confidence: bestLineProx * 0.4 + textScore * 0.6 });
    }
  }
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
  return { matches, unmatchedFindings: findings.map((_, i) => i).filter(i => !matchedFindings.has(i)) };
}

function scoreProject(manifest: ProjectManifest, review: ReviewerOutput) {
  const { matches, unmatchedFindings } = matchFindings(manifest.issues, review.findings);

  const issueScores = manifest.issues.map(issue => {
    const match = matches.find(m => manifest.issues[m.issueIndex] === issue);
    const finding = match ? review.findings[match.findingIndex] : null;

    if (!finding) {
      return { issue_id: issue.id, matched: false, raw_score: 0, weighted_score: 0, difficulty_multiplier: DIFFICULTY_MULTIPLIERS[issue.difficulty_tier] };
    }

    const detection = 1.0;
    const normalizedSev = normalizeSeverity(finding.severity);
    let severity_score = 0;
    if (normalizedSev) { const dist = severityDistance(issue.severity, normalizedSev); severity_score = dist === 0 ? 0.5 : dist === 1 ? 0.25 : 0; }

    const normalizedCWE = normalizeCWE(finding.cwe);
    let cwe_score = 0;
    if (normalizedCWE && normalizedCWE === issue.cwe_id) cwe_score = 0.5;
    else if (normalizedCWE && issue.cwe_id) { const d = Math.abs(parseInt(issue.cwe_id.replace("CWE-", "")) - parseInt(normalizedCWE.replace("CWE-", ""))); if (d <= 5) cwe_score = 0.25; }

    let location_score = 0;
    for (const loc of issue.files) {
      if (pathsMatch(loc.path, finding.file)) {
        const prox = lineProximity(loc.line_start, finding.line);
        if (prox >= 0.75) { location_score = 0.5; break; } else location_score = Math.max(location_score, 0.25);
      }
    }

    const fix_score = finding.fix && finding.fix.trim().length > 20 ? 1.0 : 0;
    const explanation_score = finding.description && finding.description.trim().length > 50 ? 0.5 : 0;
    const raw_score = detection + severity_score + cwe_score + location_score + fix_score + explanation_score;
    const multiplier = DIFFICULTY_MULTIPLIERS[issue.difficulty_tier];

    return { issue_id: issue.id, matched: true, raw_score, weighted_score: raw_score * multiplier, difficulty_multiplier: multiplier };
  });

  // Red herrings
  let rhFlagged = 0;
  for (const fi of unmatchedFindings) {
    const f = review.findings[fi];
    for (const rh of manifest.red_herrings) {
      if (rh.files.some(loc => pathsMatch(loc.path, f.file)) && textSimilarity(rh.title + " " + rh.description, f.title + " " + f.description) >= 0.25) { rhFlagged++; break; }
    }
  }
  const pureFalsePositives = unmatchedFindings.length - rhFlagged;

  // Category scores
  const categories: IssueCategory[] = ["SEC", "LOGIC", "PERF", "BP", "SMELL", "TRICKY"];
  const byCategory: Record<string, any> = {};
  for (const cat of categories) {
    const catScores = issueScores.filter(s => { const issue = manifest.issues.find(i => i.id === s.issue_id); return issue?.category === cat; });
    const tp = catScores.filter(s => s.matched).length;
    const fn = catScores.filter(s => !s.matched).length;
    const fp = unmatchedFindings.filter(fi => normalizeCategory(review.findings[fi].category) === cat).length;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const weightedScore = catScores.reduce((sum, s) => sum + s.weighted_score, 0);
    const catIssues = manifest.issues.filter(i => i.category === cat);
    const maxPossible = catIssues.reduce((sum, i) => sum + 4.0 * DIFFICULTY_MULTIPLIERS[i.difficulty_tier], 0);
    const normalizedScore = maxPossible > 0 ? weightedScore / maxPossible : 0;
    byCategory[cat] = { true_positives: tp, false_negatives: fn, false_positives: fp, precision, recall, f1, normalized_score: normalizedScore };
  }

  // Difficulty tiers
  const byDifficultyTier: Record<number, any> = {};
  for (const tier of [1, 2, 3, 4, 5] as DifficultyTier[]) {
    const tierIssues = manifest.issues.filter(i => i.difficulty_tier === tier);
    const tierMatched = issueScores.filter(s => { const issue = manifest.issues.find(i => i.id === s.issue_id); return issue?.difficulty_tier === tier && s.matched; }).length;
    byDifficultyTier[tier] = { count: tierIssues.length, matched: tierMatched, recall: tierIssues.length > 0 ? tierMatched / tierIssues.length : 0 };
  }

  // Composite
  const totalMaxPossible = manifest.issues.reduce((sum, i) => sum + 4.0 * DIFFICULTY_MULTIPLIERS[i.difficulty_tier], 0);
  const fpPenalty = (pureFalsePositives * 1.0 + rhFlagged * 2.0) / totalMaxPossible;
  let compositeScore = 0;
  for (const cat of categories) compositeScore += CATEGORY_WEIGHTS[cat] * byCategory[cat].normalized_score;
  compositeScore = Math.max(0, compositeScore - fpPenalty);

  return {
    project: manifest.project,
    total_issues: manifest.total_issues,
    total_red_herrings: manifest.total_red_herrings,
    matched_issues: matches.length,
    missed_issues: manifest.total_issues - matches.length,
    false_positives: pureFalsePositives,
    red_herrings_flagged: rhFlagged,
    composite_score: compositeScore,
    by_category: byCategory,
    by_difficulty_tier: byDifficultyTier,
  };
}

// ─── API Handler ────────────────────────────────────────────────────────────

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method === "GET") {
    return res.status(200).json({
      service: "TRASHFIRE Scoring API",
      projects: MANIFEST_PROJECTS,
      usage: "POST /api/score with { project, review: { findings: [...] } }",
    });
  }

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  // Rate limiting
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || "unknown";
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Rate limited. Try again in 1 minute.", limit: RATE_LIMIT, window: "60s" });
  }

  // Passphrase from env
  const passphrase = process.env.TRASHFIRE_KEY;
  if (!passphrase) return res.status(500).json({ error: "Scoring service not configured" });

  try {
    const body = req.body;
    if (!body || !body.project || !body.review) {
      return res.status(400).json({
        error: "Invalid request. Expected: { project: string, review: { findings: [...] } }",
        projects: MANIFEST_PROJECTS,
      });
    }

    const { project, review } = body;

    if (!MANIFESTS[project]) {
      return res.status(404).json({ error: `Unknown project: ${project}`, projects: MANIFEST_PROJECTS });
    }

    if (!review.findings || !Array.isArray(review.findings)) {
      return res.status(400).json({ error: "review.findings must be an array" });
    }

    // Validate findings have required fields
    for (let i = 0; i < review.findings.length; i++) {
      const f = review.findings[i];
      if (!f.file || !f.title) {
        return res.status(400).json({ error: `Finding ${i} missing required fields (file, title)` });
      }
      f.line = f.line || 0;
      f.severity = f.severity || "LOW";
      f.category = f.category || "SEC";
      f.description = f.description || f.title;
    }

    // Decrypt manifest and score
    const manifest = loadManifest(project, passphrase);
    const report = scoreProject(manifest, review as ReviewerOutput);

    return res.status(200).json(report);
  } catch (err: any) {
    console.error("Scoring error:", err.message);
    return res.status(500).json({ error: "Scoring failed. Check your input format." });
  }
}
