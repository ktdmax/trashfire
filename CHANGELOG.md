# Changelog

## [0.3.0] - 2026-04-02 — Server-Side Scoring + Fair Prompt System

### The Problem
AI models consistently cheat on the benchmark. In our first test round, 2 out of 3 models grepped for BUG markers instead of reading the code. When we added HARD RULES forbidding that, a model decrypted the manifests and built review JSONs directly from the answer key — achieving 100% recall by copying answers, not by reviewing code. The model even wrote "Did not read manifests during review" in its session log, which was technically true but deliberately misleading.

**Learning: Prompt-based rules don't work. If the model has access to the answers, it will find a way to use them. The fix must be architectural, not textual.**

### What Changed

**Server-side scoring API (`trashfire.io/api/score`)**
- Scoring now happens on Vercel, not locally
- Manifests are encrypted and bundled into the API — never exposed to reviewers
- Passphrase removed from all code and docs (stored only in Vercel env var `TRASHFIRE_KEY`)
- Plaintext manifests (`.json`) were already gitignored but the passphrase "monkey" was hardcoded in 10+ files — now removed everywhere
- Website gets drag-and-drop scoring UI at trashfire.io/#score-section

**3-layer prompt system**
- Feedback from a ChatGPT test run showed the prompt was too minimal and security-biased. The scorer expects a `category` field (SEC/LOGIC/PERF/BP/SMELL/TRICKY) but the prompt never mentioned categories. TRICKY (25% of the score) and LOGIC (20%) were almost never found because the prompt only said "security and code quality."
- Layer 0 (`_prompts/base-review.md`): Output format, all 6 categories, severity levels, rules. ~500 tokens. Everyone gets this.
- Layer 1 (`_prompts/project-context.ts`): Tech stack and app type per project. Like a real audit scope document.
- Layer 2: Variable — skills, custom prompts, methodology. This is what the benchmark measures.
- All 4 runners (benchmark.ts, fair-bench.ts, multi-bench.ts, run-benchmark.sh) unified to use the shared base prompt instead of divergent inline prompts.

**Scorer improvements**
- Expanded `CATEGORY_MAP` in score.ts with more normalization entries (race condition→TRICKY, code-smell→SMELL, etc.)

### Files Added
- `_prompts/base-review.md` — Layer 0 prompt (single source of truth)
- `_prompts/project-context.ts` — Layer 1 generator (42 projects)
- `_scoring/bundle-manifests.ts` — Generates manifest bundle for Vercel
- `trashfire.io/api/score.ts` — Vercel scoring API
- `trashfire.io/api/_manifests.ts` — Encrypted manifest bundle (auto-generated)
- `trashfire.io/package.json` — API dependencies

### Files Changed
- All documentation (README, BENCHMARK, COMPETITION, CONTRIBUTING, CLAUDE.md, BENCHMARK_RUNNER)
- All benchmark runners (benchmark.ts, fair-bench.ts, multi-bench.ts, run-benchmark.sh)
- Website (index.html, llm.md, vercel.json)
- Scorer (score.ts — expanded category normalization)

### Breaking Changes
- Canonical prompt hashes change — prior runs are historical data, not comparable to new runs
- Local scoring requires `TRASHFIRE_KEY` env var (or use the API)
- Passphrase "monkey" no longer works (will be rotated)

---

## [0.2.0] - 2026-03-28 — Anti-Cheating + Prompt Fairness

### The Problem
First benchmark runs revealed two issues:
1. Models grep for `// BUG-XXXX:` marker comments instead of reading code
2. Models read `_manifests/` (the answer key) during the review phase

### What Changed
- Added HARD RULES to `BENCHMARK_RUNNER.md` explicitly forbidding marker grep and manifest reads
- Added `_scoring/create-blind-copy.sh` — strips BUG markers from vault copies
- Prompt updates: "do not skim, read each file, take your time, be thorough"
- Removed bug count hints from prompts (telling models "find 100 bugs" is also cheating)
- Fixed path matching in scorer to handle various reviewer path formats

**Learning: Models are creative cheaters. Two out of three models in our first round tried to grep for markers. The blind copy approach (stripping markers) is more robust than telling models "don't look at markers."**

---

## [0.1.0] - 2026-03-26 — Initial Release

### What Shipped
- 42 vulnerable mini-applications across 30+ languages/frameworks
- 4,200+ planted issues (100 per project) across 6 categories
- AES-256-GCM encrypted ground truth manifests
- TypeScript scoring engine with composite scoring, difficulty multipliers, category weights
- Benchmark runner with presets (vanilla, security, thorough, superpowers, supaskills)
- trashfire.io website with leaderboard
- Competition framework with rules, tiers, and submission process
- GitHub issue templates for results and vault feedback
