# TRASHFIRE Benchmark - Official Test Protocol

## The Challenge

You are reviewing a real codebase for bugs, vulnerabilities, and quality issues.
This is a standardized benchmark. Your results will be compared against other AI models.

**Rules:**
- You get ONE project (one folder with source code)
- You must read EVERY file
- You report everything you find
- Your output is scored against an encrypted ground truth
- Same input, same rules, same scoring for every model

**What counts:**
- Security vulnerabilities (SQL injection, XSS, auth bypass, RCE, SSRF, IDOR, ...)
- Logic bugs (race conditions, off-by-one, wrong comparisons, null handling, ...)
- Performance issues (N+1 queries, memory leaks, blocking I/O, ...)
- Best practice violations (hardcoded secrets, swallowed errors, weak crypto, ...)
- Tricky cross-module bugs (issues that only appear when functions interact)
- NOT finding false positives (you lose points for wrong findings)

**Fair play:** No internet search. No looking at other files in the repo outside the project folder. Just read the code and find the issues.

---

## How To Run

### Step 1: Pick a project

Start with `grog-shop` (Next.js e-commerce app, 17 files).

The project is in `vaults/grog-shop/` (annotated) or `_blind/grog-shop/` (markers stripped for blind testing).

### Step 2: Give your AI the review prompt

The review prompt lives in `_prompts/base-review.md`. It defines:
- The JSON output format (required for scoring)
- All 6 issue categories: SEC, LOGIC, PERF, BP, SMELL, TRICKY
- Severity levels and precision requirements

Copy-paste its contents, or use one of the runners that load it automatically.

---

## The Prompt

The canonical prompt is built from three layers (see `BENCHMARK_RUNNER.md` for details):

| Layer | What | Same for everyone? |
|-------|------|-------------------|
| **0 — Base** | Output format, categories, severity, rules | Yes, always |
| **1 — Context** | Tech stack, app type, languages | Yes, per project |
| **2 — Skill** | Your methodology, prompts, skills | **No — this is what you're testing** |

For a vanilla run, just use Layer 0 + Layer 1 (the base prompt + project info).
For a skill run, add your skill/prompt as Layer 2.

**Quick start** — paste this into your AI tool:

```
[contents of _prompts/base-review.md]

## Project: grog-shop
- Stack: Next.js 15, Prisma, NextAuth, Stripe
- Type: E-commerce platform
- Languages: TypeScript, JavaScript

Now read every file in this project and find all issues.
```

Or use the automated runners:
```bash
./run-benchmark.sh grog-shop           # interactive preset selection
npx tsx _scoring/benchmark.ts --preset vanilla --project grog-shop
```

### Step 3: Let it read all files and produce the JSON

### Step 4: Save the JSON output as `review.json`

### Step 5: Score it

```bash
cd trashfire
curl -s -X POST https://trashfire.io/api/score \
  -H "Content-Type: application/json" \
  -d "{\"project\": \"grog-shop\", \"review\": $(cat review.json)}" | jq .

# Or upload review.json at https://trashfire.io/#score-section
```

The report shows your composite score, per-category breakdown, and what was found vs missed.

---

## How To Run In Each Tool

### Claude Code (CLI / Desktop / IDE)

```bash
# Automated (recommended)
./run-benchmark.sh grog-shop

# Manual
cd trashfire/_blind/grog-shop
claude -p "$(cat ../../_prompts/base-review.md)" --output-format text > review.json
```

### Any AI Tool (Codex, Gemini, Cursor, Aider, ...)

1. Open the tool in `_blind/grog-shop/` (or upload the folder)
2. Paste the contents of `_prompts/base-review.md` as the prompt
3. Add project context: "Project: grog-shop, Stack: Next.js 15 + Prisma + NextAuth"
4. Tell it to read all files and output findings as JSON
5. Save the JSON output as `review.json`

---

## Scoring

| Component | Points |
|-----------|--------|
| Found the issue | 1.0 |
| Correct severity | +0.5 |
| Correct CWE | +0.5 |
| Correct file + line | +0.5 |
| Working fix | +1.0 |
| Good explanation | +0.5 |
| **Max per issue** | **4.0** |

**Penalties:**
- False positive: -1.0
- Flagging safe code as vulnerable: -2.0

**Difficulty multipliers:** Easy bugs (x1.0) to expert-level bugs (x3.0).
Finding a hard bug is worth 3x more than finding an obvious one.

**Category weights:** Security 35% | Tricky 25% | Logic 20% | Performance 10% | Best Practice 5% | Code Smell 5%

## Current Leaderboard

See [LEADERBOARD.md](LEADERBOARD.md) or [trashfire.io](https://trashfire.io)

---

*May the best model win.* 🔥
