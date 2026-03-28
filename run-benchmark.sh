#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════╗
# ║  TRASHFIRE - Run a benchmark in one command              ║
# ╚═══════════════════════════════════════════════════════════╝
#
# Usage:
#   ./run-benchmark.sh                          # Interactive mode
#   ./run-benchmark.sh grog-shop                # Review one project
#   ./run-benchmark.sh grog-shop "Your prompt"  # With custom prompt
#
# What it does:
#   1. Opens the blind code in Claude Code
#   2. Claude reviews it and writes findings JSON
#   3. Scores the findings against encrypted ground truth
#   4. Shows the report
#
# Requirements: claude CLI, node/npx

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BLIND="$ROOT/_blind"
MANIFESTS="$ROOT/_manifests"
SCORING="$ROOT/_scoring"
RESULTS="$ROOT/_results"
PASSPHRASE="${TRASHFIRE_KEY:-monkey}"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${RED}${BOLD}  TRASHFIRE${NC} - AI Code Review Benchmark"
echo -e "  ════════════════════════════════════════"
echo ""

# ── Pick project ──
if [ -n "${1:-}" ]; then
  PROJECT="$1"
else
  echo -e "  ${CYAN}Available projects:${NC}"
  echo ""
  ls -1 "$BLIND" | grep -v "^_" | grep -v "node_modules" | column -c 80 | sed 's/^/    /'
  echo ""
  read -p "  Pick a project (default: grog-shop): " PROJECT
  PROJECT="${PROJECT:-grog-shop}"
fi

if [ ! -d "$BLIND/$PROJECT" ]; then
  echo -e "  ${RED}Error: Project '$PROJECT' not found in $BLIND/${NC}"
  exit 1
fi

echo -e "  ${GREEN}Project:${NC} $PROJECT"

# ── Pick prompt ──
if [ -n "${2:-}" ]; then
  PROMPT="$2"
else
  echo ""
  echo -e "  ${CYAN}Prompt presets:${NC}"
  echo "    1) vanilla    - 'Review this code for issues'"
  echo "    2) expert     - Detailed security focus"
  echo "    3) dev-savvy  - Experienced developer, all categories"
  echo "    4) custom     - Type your own prompt"
  echo ""
  read -p "  Pick a preset (1-4, default: 1): " PRESET_CHOICE
  PRESET_CHOICE="${PRESET_CHOICE:-1}"

  case "$PRESET_CHOICE" in
    1) PROMPT="Review this codebase for any issues you can find. Check all the files." ; PRESET="vanilla" ;;
    2) PROMPT="You are an expert security reviewer. Review this codebase for security vulnerabilities. Check every file thoroughly for: SQL injection, XSS, auth bypass, RCE, SSRF, IDOR, CSRF, path traversal, command injection, deserialization, hardcoded secrets, weak crypto, and any other security issues." ; PRESET="expert" ;;
    3) PROMPT="Review all files as an experienced senior developer. Find: security bugs (SQLi, XSS, auth issues, injection, SSRF, IDOR), logic errors (race conditions, off-by-one, wrong comparisons, async problems), performance problems (N+1 queries, memory leaks, blocking calls), bad practices (hardcoded values, swallowed errors, missing validation, weak crypto), and tricky cross-function bugs. Think about edge cases: empty arrays, negative numbers, concurrent requests, float arithmetic for money." ; PRESET="dev-savvy" ;;
    4) read -p "  Enter your prompt: " PROMPT ; PRESET="custom" ;;
    *) PROMPT="Review this codebase for any issues you can find. Check all the files." ; PRESET="vanilla" ;;
  esac
fi
PRESET="${PRESET:-custom}"

echo -e "  ${GREEN}Preset:${NC}  $PRESET"

# ── Setup output ──
TIMESTAMP=$(date +%s)
RUN_ID="${PRESET}-${PROJECT}-${TIMESTAMP}"
RUN_DIR="$RESULTS/$RUN_ID"
mkdir -p "$RUN_DIR"
REVIEW_FILE="$RUN_DIR/${PROJECT}-review.json"

echo ""
echo -e "  ${YELLOW}Step 1/3: Running review...${NC}"
echo -e "  This takes 2-5 minutes depending on project size."
echo ""

# ── Run the review via Claude ──
REVIEW_PROMPT="$PROMPT

After reviewing ALL files, output your complete findings as a single JSON object in this EXACT format. Write ONLY valid JSON, no other text:

{
  \"reviewer\": \"claude-opus-4-6\",
  \"project\": \"$PROJECT\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"findings\": [
    {
      \"file\": \"$PROJECT/path/to/file.ext\",
      \"line\": 42,
      \"severity\": \"CRITICAL\",
      \"category\": \"security\",
      \"cwe\": \"CWE-89\",
      \"title\": \"Short description of the issue\",
      \"description\": \"Detailed explanation of what is wrong and why it matters\",
      \"fix\": \"How to fix this issue\"
    }
  ]
}"

# Run claude and capture output
claude -p "$REVIEW_PROMPT" --output-format text -c "$BLIND/$PROJECT" 2>/dev/null | tee "$RUN_DIR/raw-output.txt" | grep -v "^$" > /dev/null

# Extract JSON from output
node -e "
const fs = require('fs');
const raw = fs.readFileSync('$RUN_DIR/raw-output.txt', 'utf-8');
const match = raw.match(/\{[\s\S]*\"findings\"[\s\S]*\}/);
if (match) {
  try {
    const parsed = JSON.parse(match[0]);
    fs.writeFileSync('$REVIEW_FILE', JSON.stringify(parsed, null, 2));
    console.log('  Findings extracted: ' + parsed.findings.length + ' issues found');
  } catch(e) {
    console.log('  Warning: JSON parse failed, trying to fix...');
    fs.writeFileSync('$REVIEW_FILE', match[0]);
  }
} else {
  console.log('  Warning: No JSON found in output');
  const empty = { reviewer: 'claude', project: '$PROJECT', timestamp: new Date().toISOString(), findings: [] };
  fs.writeFileSync('$REVIEW_FILE', JSON.stringify(empty, null, 2));
}
"

# ── Score it ──
echo ""
echo -e "  ${YELLOW}Step 2/3: Scoring against ground truth...${NC}"

MANIFEST="$MANIFESTS/${PROJECT}.enc"
if [ ! -f "$MANIFEST" ]; then
  echo -e "  ${RED}Error: No manifest found for $PROJECT${NC}"
  exit 1
fi

REPORT_FILE="$RUN_DIR/report.md"
echo "$PASSPHRASE" | npx --prefix "$SCORING" tsx "$SCORING/score.ts" \
  --manifest "$MANIFEST" \
  --review "$REVIEW_FILE" \
  --output "$REPORT_FILE" 2>/dev/null

# ── Show results ──
echo ""
echo -e "  ${YELLOW}Step 3/3: Results${NC}"
echo -e "  ════════════════════════════════════════"
echo ""

if [ -f "$REPORT_FILE" ]; then
  cat "$REPORT_FILE"
else
  echo -e "  ${RED}Scoring failed. Check $RUN_DIR/ for details.${NC}"
fi

echo ""
echo -e "  ════════════════════════════════════════"
echo -e "  ${GREEN}Results saved to:${NC} $RUN_DIR/"
echo -e "  ${GREEN}Files:${NC}"
echo "    - report.md       (human-readable report)"
echo "    - report.json     (machine-readable scores)"
echo "    - ${PROJECT}-review.json  (raw findings)"
echo ""
