// ─── Issue Categories ────────────────────────────────────────────────────────

export type IssueCategory = "SEC" | "LOGIC" | "PERF" | "BP" | "SMELL" | "TRICKY";

export type IssueSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type DifficultyTier = 1 | 2 | 3 | 4 | 5;

export const DIFFICULTY_MULTIPLIERS: Record<DifficultyTier, number> = {
  1: 1.0,
  2: 1.25,
  3: 1.5,
  4: 2.0,
  5: 3.0,
};

export const CATEGORY_WEIGHTS: Record<IssueCategory, number> = {
  SEC: 0.35,
  LOGIC: 0.20,
  PERF: 0.10,
  BP: 0.05,
  SMELL: 0.05,
  TRICKY: 0.25,
};

// ─── Tricky Patterns ─────────────────────────────────────────────────────────

export type TrickyPattern =
  | "TRICKY-CHAIN"
  | "TRICKY-EDGE"
  | "TRICKY-RACE"
  | "TRICKY-ENV"
  | "TRICKY-COERCE"
  | "TRICKY-IMPORT"
  | "TRICKY-CONFIG"
  | "TRICKY-DEPVER"
  | "TRICKY-LOCALE"
  | "TRICKY-BIZLOGIC"
  | "TRICKY-PROTO"
  | "TRICKY-CACHE"
  | "TRICKY-SERIAL"
  | "TRICKY-FLOAT"
  | "TRICKY-REGEX";

// ─── Issue File Location ─────────────────────────────────────────────────────

export interface IssueFileLocation {
  path: string;
  line_start: number;
  line_end: number;
  snippet_hash: string; // sha256 of the vulnerable code snippet
}

// ─── Issue ───────────────────────────────────────────────────────────────────

export interface Issue {
  id: string; // BUG-XXXX (project-scoped, e.g. BUG-0001)
  project: string;
  category: IssueCategory;
  secondary_category: IssueCategory | null; // for TRICKY issues
  tricky_pattern: TrickyPattern | null; // only for TRICKY category
  severity: IssueSeverity;
  difficulty_tier: DifficultyTier;
  cvss_score: number; // 0.0 - 10.0
  cvss_vector: string;
  cwe_id: string; // e.g. "CWE-89"
  cwe_name: string;
  owasp_category: string | null; // e.g. "A03:2021"
  pattern: string; // sub-taxonomy pattern ID e.g. "SEC-SQLI"
  title: string;
  description: string;
  files: IssueFileLocation[];
  cross_references: IssueFileLocation[]; // related locations for multi-file bugs
  exploit_description: string;
  fix_description: string;
  fix_diff: string;
  tags: string[];
  detection_hints: {
    keywords: string[];
    minimum_context_files: number;
    requires_data_flow_analysis: boolean;
  };
}

// ─── Red Herring ─────────────────────────────────────────────────────────────

export interface RedHerring {
  id: string; // RH-XXX
  project: string;
  apparent_category: IssueCategory;
  apparent_severity: IssueSeverity;
  apparent_cwe: string;
  title: string;
  description: string;
  files: IssueFileLocation[];
  why_safe: string;
  tags: string[];
}

// ─── Project Manifest ────────────────────────────────────────────────────────

export interface ProjectManifest {
  project: string;
  version: string;
  generated_at: string; // ISO 8601
  total_issues: number;
  total_red_herrings: number;
  distribution: {
    by_severity: Record<IssueSeverity, number>;
    by_category: Record<IssueCategory, number>;
    by_difficulty_tier: Record<DifficultyTier, number>;
  };
  issues: Issue[];
  red_herrings: RedHerring[];
  metadata: {
    tech_stack: string;
    primary_language: string;
    secondary_languages: string[];
    focus_areas: string[];
  };
}

// ─── Reviewer Finding (input from the LLM review) ───────────────────────────

export interface ReviewerFinding {
  id?: string; // optional, reviewer-assigned
  file: string;
  line: number;
  severity: string; // free text, will be normalized
  category: string; // free text, will be normalized
  cwe?: string;
  title: string;
  description: string;
  fix?: string;
}

export interface ReviewerOutput {
  reviewer: string; // model name / tool name
  project: string;
  timestamp: string;
  findings: ReviewerFinding[];
}

// ─── Scoring Results ─────────────────────────────────────────────────────────

export interface IssueScore {
  issue_id: string;
  matched: boolean;
  finding_index: number | null; // index into reviewer findings
  detection: number; // 0 or 1.0
  severity_score: number; // 0, 0.25, or 0.5
  cwe_score: number; // 0, 0.25, or 0.5
  location_score: number; // 0, 0.25, or 0.5
  fix_score: number; // 0 or 1.0
  explanation_score: number; // 0 or 0.5
  raw_score: number; // sum of above (max 4.0)
  difficulty_multiplier: number;
  weighted_score: number; // raw * multiplier
}

export interface CategoryScore {
  category: IssueCategory;
  true_positives: number;
  false_negatives: number;
  false_positives: number;
  precision: number;
  recall: number;
  f1: number;
  weighted_score: number; // sum of weighted issue scores
  max_possible: number; // sum of max possible weighted scores
  normalized_score: number; // weighted_score / max_possible (0.0 - 1.0)
}

export interface ProjectScoreReport {
  project: string;
  reviewer: string;
  timestamp: string;
  total_issues: number;
  total_red_herrings: number;
  matched_issues: number;
  missed_issues: number;
  false_positives: number;
  red_herrings_flagged: number;
  false_positive_penalty: number;
  by_category: Record<IssueCategory, CategoryScore>;
  by_difficulty_tier: Record<DifficultyTier, { recall: number; count: number; matched: number }>;
  composite_score: number; // 0.0 - 1.0 (floored at 0)
  issue_scores: IssueScore[];
}

export interface BenchmarkReport {
  reviewer: string;
  benchmark_version: string;
  run_timestamp: string;
  aggregate: {
    mean_score: number;
    median_score: number;
    worst_project: { project: string; score: number };
    best_project: { project: string; score: number };
    total_tp: number;
    total_fp: number;
    total_fn: number;
    total_rh_flagged: number;
    overall_precision: number;
    overall_recall: number;
  };
  by_category: Record<IssueCategory, { precision: number; recall: number; f1: number; weighted_score: number }>;
  by_difficulty_tier: Record<DifficultyTier, { recall: number }>;
  projects: ProjectScoreReport[];
}

// ─── Crypto Format Constants ─────────────────────────────────────────────────

export const TFBM_MAGIC = Buffer.from("TFBM");
export const TFBM_VERSION = 1;
export const SALT_LENGTH = 32;
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const PBKDF2_ITERATIONS = 600_000;
export const KEY_LENGTH = 32; // 256 bits
