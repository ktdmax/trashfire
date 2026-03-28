#!/usr/bin/env npx tsx
/**
 * extract-manifest.ts
 *
 * Parses BUG-XXXX and RH-XXX comments from project source files
 * and generates a ProjectManifest JSON file.
 *
 * Usage: npx tsx extract-manifest.ts <project-dir> [--out <path>]
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { createHash } from "node:crypto";
import type {
  Issue,
  RedHerring,
  ProjectManifest,
  IssueCategory,
  IssueSeverity,
  DifficultyTier,
  TrickyPattern,
  IssueFileLocation,
} from "./types.js";

// ─── File Extensions to Scan ─────────────────────────────────────────────────

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".pyi",
  ".go",
  ".rs",
  ".java", ".kt", ".kts", ".scala",
  ".rb", ".erb",
  ".php",
  ".c", ".cpp", ".cc", ".h", ".hpp",
  ".cs",
  ".swift",
  ".ex", ".exs",
  ".hs",
  ".jl",
  ".r", ".R",
  ".pl", ".pm", ".ep",
  ".zig",
  ".sol",
  ".dart",
  ".html", ".css", ".svelte", ".vue",
  ".sql",
  ".yaml", ".yml", ".toml", ".json",
  ".tf", ".hcl",
  ".sh", ".bash",
  ".conf", ".env", ".example",
  ".proto",
  ".prisma",
]);

// ─── Recursively Find Files ──────────────────────────────────────────────────

function findFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "__pycache__" || entry.name === "target" || entry.name === "_build") continue;
      results.push(...findFiles(full));
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      // Also scan files without extension (like Dockerfile, Makefile, Gemfile)
      if (SCAN_EXTENSIONS.has(ext) || ["Dockerfile", "Makefile", "Gemfile", "cpanfile", "Rakefile"].includes(entry.name)) {
        results.push(full);
      }
    }
  }
  return results;
}

// ─── Parse Bug Comment ───────────────────────────────────────────────────────

// Matches patterns like:
//   // BUG-0001: SQL injection via raw query (CWE-89, CVSS 9.8, CRITICAL, Tier 2)
//   # BUG-042: description (CWE-79, CVSS 7.5, HIGH, Tier 3)
//   -- BUG-0001: description (CWE-89, CVSS 9.8, CRITICAL, Tier 2)
//   /* BUG-0001: description */
// Also handles variants: BUG-001, BUG-0001, BUG-1
const BUG_PATTERN = /BUG-0*(\d+)\s*:\s*(.+)/i;
const RH_PATTERN = /(?:RH|RED-HERRING)-0*(\d+)\s*:\s*(.+)/i;

// Extract metadata from the description text
const CWE_PATTERN = /CWE-(\d+)/i;
const CVSS_PATTERN = /CVSS\s*(\d+\.?\d*)/i;
const SEVERITY_PATTERN = /\b(CRITICAL|HIGH|MEDIUM|LOW|BEST.?PRACTICE)\b/i;
const TIER_PATTERN = /Tier\s*(\d)/i;

interface ParsedBug {
  id: string;
  numericId: number;
  description: string;
  cweId: string | null;
  cvssScore: number;
  severity: IssueSeverity;
  tier: DifficultyTier;
  filePath: string;
  lineNumber: number;
  snippetHash: string;
}

interface ParsedRedHerring {
  id: string;
  numericId: number;
  description: string;
  filePath: string;
  lineNumber: number;
}

function extractSnippetHash(lines: string[], lineIdx: number): string {
  // Hash a window of ±3 lines around the bug marker
  const start = Math.max(0, lineIdx - 3);
  const end = Math.min(lines.length, lineIdx + 4);
  const snippet = lines.slice(start, end).join("\n");
  return "sha256:" + createHash("sha256").update(snippet).digest("hex").slice(0, 16);
}

function parseSeverity(raw: string): IssueSeverity {
  const normalized = raw.toUpperCase().replace(/[^A-Z]/g, "");
  if (normalized.includes("CRITICAL")) return "CRITICAL";
  if (normalized.includes("HIGH")) return "HIGH";
  if (normalized.includes("MEDIUM") || normalized.includes("MODERATE")) return "MEDIUM";
  return "LOW";
}

function parseTier(raw: string | null): DifficultyTier {
  if (!raw) return 2;
  const num = parseInt(raw);
  if (num >= 1 && num <= 5) return num as DifficultyTier;
  return 2;
}

function guessCategory(description: string, severity: IssueSeverity, tier: DifficultyTier): IssueCategory {
  const desc = description.toLowerCase();

  // Check for TRICKY patterns
  if (tier >= 4) return "TRICKY";
  if (desc.includes("race condition") || desc.includes("toctou") || desc.includes("timing") ||
      desc.includes("cross-module") || desc.includes("chain") || desc.includes("edge case") ||
      desc.includes("type coercion") || desc.includes("type juggling") || desc.includes("prototype pollution") ||
      desc.includes("cache poison") || desc.includes("float") || desc.includes("locale") ||
      desc.includes("encoding trap") || desc.includes("regex state") || desc.includes("import order") ||
      desc.includes("config drift") || desc.includes("dependency version") || desc.includes("serialization boundary")) {
    return "TRICKY";
  }

  // Check for performance
  if (desc.includes("n+1") || desc.includes("memory leak") || desc.includes("blocking") ||
      desc.includes("performance") || desc.includes("re-render") || desc.includes("redos") ||
      desc.includes("unbounded") || desc.includes("inefficient")) {
    return "PERF";
  }

  // Check for best practice
  if (desc.includes("best practice") || desc.includes("deprecated") || desc.includes("hardcoded") ||
      desc.includes("missing error") || desc.includes("bare except") || desc.includes("mutable default") ||
      desc.includes("dead code") || desc.includes("magic number") || desc.includes("god function") ||
      desc.includes("copy-paste") || desc.includes("missing type") || desc.includes("global state") ||
      desc.includes("error swallow") || desc.includes("unchecked") || desc.includes("missing const")) {
    if (severity === "LOW") return "BP";
    return "SMELL";
  }

  // Check for code smells
  if (desc.includes("code smell") || desc.includes("duplication") || desc.includes("complexity") ||
      desc.includes("nesting") || desc.includes("maintainab")) {
    return "SMELL";
  }

  // Check for logic bugs
  if (desc.includes("off-by-one") || desc.includes("wrong operator") || desc.includes("logic") ||
      desc.includes("negation") || desc.includes("null check") || desc.includes("state machine") ||
      desc.includes("missing await") || desc.includes("boundary")) {
    return "LOGIC";
  }

  // Default: security
  return "SEC";
}

function guessTrickyPattern(description: string): TrickyPattern | null {
  const desc = description.toLowerCase();
  if (desc.includes("chain") || desc.includes("cross-module")) return "TRICKY-CHAIN";
  if (desc.includes("edge case") || desc.includes("edge-case") || desc.includes("rare")) return "TRICKY-EDGE";
  if (desc.includes("race") || desc.includes("toctou") || desc.includes("concurrent")) return "TRICKY-RACE";
  if (desc.includes("environment") || desc.includes("dev vs prod") || desc.includes("prod")) return "TRICKY-ENV";
  if (desc.includes("coercion") || desc.includes("juggling") || desc.includes("loose comparison")) return "TRICKY-COERCE";
  if (desc.includes("import order") || desc.includes("circular") || desc.includes("init order")) return "TRICKY-IMPORT";
  if (desc.includes("config drift") || desc.includes("configuration")) return "TRICKY-CONFIG";
  if (desc.includes("dependency version") || desc.includes("version conflict")) return "TRICKY-DEPVER";
  if (desc.includes("locale") || desc.includes("encoding") || desc.includes("utf")) return "TRICKY-LOCALE";
  if (desc.includes("business logic") || desc.includes("exploitable logic")) return "TRICKY-BIZLOGIC";
  if (desc.includes("prototype") || desc.includes("inheritance")) return "TRICKY-PROTO";
  if (desc.includes("cache")) return "TRICKY-CACHE";
  if (desc.includes("serializ") || desc.includes("bigint") || desc.includes("json.stringify")) return "TRICKY-SERIAL";
  if (desc.includes("float") || desc.includes("precision") || desc.includes("0.1")) return "TRICKY-FLOAT";
  if (desc.includes("regex") || desc.includes("lastindex") || desc.includes("global flag")) return "TRICKY-REGEX";
  if (desc.includes("timing")) return "TRICKY-RACE";
  return "TRICKY-CHAIN"; // default tricky pattern
}

function guessCWEName(cweId: string): string {
  const map: Record<string, string> = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding",
    "CWE-200": "Information Exposure",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-311": "Missing Encryption",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of Broken Crypto Algorithm",
    "CWE-328": "Reversible One-Way Hash",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-367": "TOCTOU Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-532": "Insertion of Sensitive Info into Log",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-611": "XXE",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-639": "Authorization Bypass (IDOR)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-943": "NoSQL Injection",
  };
  return map[cweId] ?? "Security Vulnerability";
}

// ─── Main Extraction ─────────────────────────────────────────────────────────

function extractFromProject(projectDir: string, projectName: string): { bugs: ParsedBug[]; redHerrings: ParsedRedHerring[] } {
  const files = findFiles(projectDir);
  const bugs: ParsedBug[] = [];
  const redHerrings: ParsedRedHerring[] = [];
  const seenBugIds = new Set<number>();

  for (const filePath of files) {
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");
    const relPath = projectName + "/" + relative(projectDir, filePath);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for BUG markers
      const bugMatch = line.match(BUG_PATTERN);
      if (bugMatch) {
        const numericId = parseInt(bugMatch[1]);
        if (seenBugIds.has(numericId)) continue; // skip duplicates
        seenBugIds.add(numericId);

        const fullDesc = bugMatch[2].trim();
        const cweMatch = fullDesc.match(CWE_PATTERN);
        const cvssMatch = fullDesc.match(CVSS_PATTERN);
        const sevMatch = fullDesc.match(SEVERITY_PATTERN);
        const tierMatch = fullDesc.match(TIER_PATTERN);

        // Clean description: remove the parenthetical metadata
        const cleanDesc = fullDesc.replace(/\s*\(.*\)\s*$/, "").trim();

        bugs.push({
          id: `BUG-${String(numericId).padStart(4, "0")}`,
          numericId,
          description: cleanDesc,
          cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
          cvssScore: cvssMatch ? parseFloat(cvssMatch[1]) : 5.0,
          severity: sevMatch ? parseSeverity(sevMatch[1]) : "MEDIUM",
          tier: parseTier(tierMatch ? tierMatch[1] : null),
          filePath: relPath,
          lineNumber: i + 1,
          snippetHash: extractSnippetHash(lines, i),
        });
      }

      // Check for Red Herring markers
      const rhMatch = line.match(RH_PATTERN);
      if (rhMatch) {
        const numericId = parseInt(rhMatch[1]);
        const fullDesc = rhMatch[2].trim();
        const cleanDesc = fullDesc.replace(/\s*\(.*\)\s*$/, "").trim();

        redHerrings.push({
          id: `RH-${String(numericId).padStart(3, "0")}`,
          numericId,
          description: cleanDesc,
          filePath: relPath,
          lineNumber: i + 1,
        });
      }
    }
  }

  // Sort by numeric ID
  bugs.sort((a, b) => a.numericId - b.numericId);
  redHerrings.sort((a, b) => a.numericId - b.numericId);

  return { bugs, redHerrings };
}

// ─── Build Manifest ──────────────────────────────────────────────────────────

function buildManifest(projectDir: string, projectName: string): ProjectManifest {
  const { bugs, redHerrings } = extractFromProject(projectDir, projectName);

  // Convert to Issue objects
  const issues: Issue[] = bugs.map((b) => {
    const category = guessCategory(b.description, b.severity, b.tier);
    const secondaryCategory = category === "TRICKY" ? guessCategory(b.description, b.severity, 1 as DifficultyTier) : null;
    const trickyPattern = category === "TRICKY" ? guessTrickyPattern(b.description) : null;

    return {
      id: b.id,
      project: projectName,
      category,
      secondary_category: secondaryCategory !== "TRICKY" ? secondaryCategory : "SEC",
      tricky_pattern: trickyPattern,
      severity: b.severity,
      difficulty_tier: b.tier,
      cvss_score: b.cvssScore,
      cvss_vector: "",
      cwe_id: b.cweId ?? "CWE-000",
      cwe_name: b.cweId ? guessCWEName(b.cweId) : "Unknown",
      owasp_category: null,
      pattern: `${category}-${(b.cweId ?? "UNKNOWN").replace("CWE-", "")}`,
      title: b.description,
      description: b.description,
      files: [{
        path: b.filePath,
        line_start: b.lineNumber,
        line_end: b.lineNumber + 2,
        snippet_hash: b.snippetHash,
      }],
      cross_references: [],
      exploit_description: "",
      fix_description: "",
      fix_diff: "",
      tags: [],
      detection_hints: {
        keywords: b.description.toLowerCase().split(/\s+/).filter(w => w.length > 3).slice(0, 5),
        minimum_context_files: 1,
        requires_data_flow_analysis: b.tier >= 3,
      },
    };
  });

  // Convert to RedHerring objects
  const rhs: RedHerring[] = redHerrings.map((r) => ({
    id: r.id,
    project: projectName,
    apparent_category: "SEC" as IssueCategory,
    apparent_severity: "HIGH" as IssueSeverity,
    apparent_cwe: "CWE-000",
    title: r.description,
    description: r.description,
    files: [{
      path: r.filePath,
      line_start: r.lineNumber,
      line_end: r.lineNumber + 2,
      snippet_hash: "",
    }],
    why_safe: "See inline comment for explanation",
    tags: [],
  }));

  // Compute distribution
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<IssueSeverity, number>;
  const byCategory = { SEC: 0, LOGIC: 0, PERF: 0, BP: 0, SMELL: 0, TRICKY: 0 } as Record<IssueCategory, number>;
  const byTier = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 } as Record<DifficultyTier, number>;

  for (const issue of issues) {
    bySeverity[issue.severity]++;
    byCategory[issue.category]++;
    byTier[issue.difficulty_tier]++;
  }

  // Detect primary language from file extensions
  const extCounts: Record<string, number> = {};
  for (const b of bugs) {
    const ext = extname(b.filePath).toLowerCase();
    extCounts[ext] = (extCounts[ext] ?? 0) + 1;
  }
  const primaryExt = Object.entries(extCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  const langMap: Record<string, string> = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
    ".py": "Python", ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
    ".scala": "Scala", ".rb": "Ruby", ".php": "PHP", ".c": "C", ".cpp": "C++",
    ".cs": "C#", ".swift": "Swift", ".ex": "Elixir", ".hs": "Haskell", ".jl": "Julia",
    ".r": "R", ".R": "R", ".pl": "Perl", ".pm": "Perl", ".zig": "Zig",
    ".sol": "Solidity", ".dart": "Dart", ".svelte": "Svelte", ".vue": "Vue",
    ".sql": "SQL", ".tf": "HCL",
  };

  return {
    project: projectName,
    version: "1.0.0",
    generated_at: new Date().toISOString(),
    total_issues: issues.length,
    total_red_herrings: rhs.length,
    distribution: {
      by_severity: bySeverity,
      by_category: byCategory,
      by_difficulty_tier: byTier,
    },
    issues,
    red_herrings: rhs,
    metadata: {
      tech_stack: "",
      primary_language: langMap[primaryExt] ?? "Unknown",
      secondary_languages: [],
      focus_areas: [],
    },
  };
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help") {
    console.error("Usage: npx tsx extract-manifest.ts <project-dir> [--out <path>]");
    console.error("       npx tsx extract-manifest.ts --all <root-dir> [--out-dir <dir>]");
    process.exit(1);
  }

  if (args[0] === "--all") {
    // Extract all projects
    const rootDir = args[1] ?? ".";
    const outDirIdx = args.indexOf("--out-dir");
    const outDir = outDirIdx !== -1 ? args[outDirIdx + 1] : join(rootDir, "_manifests");

    const projectsDir = join(rootDir, "projects");
    const scanDir = existsSync(projectsDir) ? projectsDir : rootDir;
    const entries = readdirSync(scanDir, { withFileTypes: true });
    const projects = entries
      .filter(e => e.isDirectory() && !e.name.startsWith("_") && !e.name.startsWith(".") && e.name !== "node_modules")
      .map(e => e.name)
      .sort();

    let totalBugs = 0;
    let totalRH = 0;

    for (const project of projects) {
      const projectDir = join(scanDir, project);
      const manifest = buildManifest(projectDir, project);

      const outPath = join(outDir, `${project}.json`);
      writeFileSync(outPath, JSON.stringify(manifest, null, 2));

      totalBugs += manifest.total_issues;
      totalRH += manifest.total_red_herrings;

      console.log(`  ${project}: ${manifest.total_issues} bugs, ${manifest.total_red_herrings} red herrings → ${outPath}`);
    }

    console.log(`\nTotal: ${projects.length} projects, ${totalBugs} bugs, ${totalRH} red herrings`);
  } else {
    // Single project
    const projectDir = args[0];
    const projectName = projectDir.split("/").filter(Boolean).pop()!;
    const outIdx = args.indexOf("--out");
    const outPath = outIdx !== -1 ? args[outIdx + 1] : `_manifests/${projectName}.json`;

    const manifest = buildManifest(projectDir, projectName);
    writeFileSync(outPath, JSON.stringify(manifest, null, 2));

    console.log(`${projectName}: ${manifest.total_issues} bugs, ${manifest.total_red_herrings} red herrings → ${outPath}`);
  }
}

main();
