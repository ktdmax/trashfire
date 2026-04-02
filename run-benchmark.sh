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
PASSPHRASE="${TRASHFIRE_KEY:?Set TRASHFIRE_KEY env var for local scoring, or use https://trashfire.io/api/score}"

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

# ── Load base prompt (Layer 0) ──
BASE_PROMPT_FILE="$ROOT/_prompts/base-review.md"
if [ ! -f "$BASE_PROMPT_FILE" ]; then
  echo -e "  ${RED}Error: Base prompt not found at $BASE_PROMPT_FILE${NC}"
  exit 1
fi
BASE_PROMPT=$(cat "$BASE_PROMPT_FILE")

# ── Pick preset (Layer 2 addition) ──
if [ -n "${2:-}" ]; then
  LAYER2="$2"
  PRESET="custom"
else
  echo ""
  echo -e "  ${CYAN}Prompt presets (Layer 2 — added on top of base prompt):${NC}"
  echo "    1) vanilla    - Base prompt only (no extra guidance)"
  echo "    2) security   - Extra focus on security methodology"
  echo "    3) thorough   - Extra focus on edge cases and cross-module bugs"
  echo "    4) custom     - Type your own addition"
  echo ""
  read -p "  Pick a preset (1-4, default: 1): " PRESET_CHOICE
  PRESET_CHOICE="${PRESET_CHOICE:-1}"

  case "$PRESET_CHOICE" in
    1) LAYER2="" ; PRESET="vanilla" ;;
    2) LAYER2="Focus extra attention on security vulnerabilities. For each file: map data flows from untrusted inputs to sensitive operations, check authentication and authorization at every boundary, look for injection vectors (SQL, command, template, deserialization), verify cryptographic operations, check for hardcoded secrets and permissive CORS." ; PRESET="security" ;;
    3) LAYER2="Think like an experienced senior developer who has seen production incidents. Pay special attention to edge cases: empty arrays, negative numbers, Unicode input, concurrent requests, float arithmetic for money, TOCTOU problems, missing permission checks, error paths that skip cleanup, and state transitions that can be triggered out of order." ; PRESET="thorough" ;;
    4) read -p "  Enter your Layer 2 addition: " LAYER2 ; PRESET="custom" ;;
    *) LAYER2="" ; PRESET="vanilla" ;;
  esac
fi

echo -e "  ${GREEN}Preset:${NC}  $PRESET"

# ── Setup output ──
TIMESTAMP=$(date +%s)
RUN_ID="${PRESET}-${PROJECT}-${TIMESTAMP}"
RUN_DIR="$RESULTS/$RUN_ID"
mkdir -p "$RUN_DIR"
REVIEW_FILE="$RUN_DIR/${PROJECT}-review.json"

echo ""
echo -e "  ${YELLOW}Step 1/3: Running review...${NC}"
echo -e "  This takes 30-60 minutes per vault for a thorough review."
echo ""

# ── Compose review prompt (Layer 0 + Layer 2) ──
# Note: Layer 1 (project context) is embedded in the base prompt via project-context.ts
# For the shell script, we inline minimal project context
REVIEW_PROMPT="$BASE_PROMPT

## Project: $PROJECT"

# Append Layer 2 if present
if [ -n "$LAYER2" ]; then
  REVIEW_PROMPT="$REVIEW_PROMPT

---

## Additional Review Guidance

$LAYER2"
fi

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
