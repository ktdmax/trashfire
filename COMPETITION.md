# TRASHFIRE Open Competition

## The Mission

We know how AI reviews code out of the box. The vanilla results are in. They're not great.

**Now it's your turn.**

Build a skill, a prompt, a workflow that finds more bugs. Share it openly. Help make the internet a bit harder to exploit.

The best skill wins, ships to the community, and gets used in real code reviews by real developers.

## The Rules

Three simple rules. No loopholes.

### Rule 1: General Purpose

Your skill/prompt must be **generally applicable** to any codebase.

- It must work on code it has never seen before
- It must not contain references to specific bugs, files, or patterns from TRASHFIRE projects
- It must not encode knowledge of the ground truth in any form
- A prompt that says "check for SQL injection in the searchProducts function" is cheating
- A prompt that says "check for SQL injection in all database query functions" is fair game

**The test:** Would your skill be useful on a completely different codebase? If yes, it's valid.

### Rule 2: Public and Open

Your submission must be **publicly available**.

- Published as a GitHub repo, gist, SupaSkills skill, or PR to this repo
- Anyone can inspect it, use it, and build on it
- No hidden system prompts, no obfuscated instructions
- The whole point is that the community benefits

### Rule 3: Fair Play

No gaming the benchmark. No cheating. No shortcuts.

- **DO NOT grep/search for BUG-XXX or RH-XXX markers.** That is cheating, not reviewing. Two out of three models tried this in our first test round. It's immediately obvious and your result is invalid.
- **DO NOT read _manifests/ files.** That is the answer key.
- **Always use the blind copy (_blind/) or strip markers first.** The vaults/ folder contains annotations.
- Don't train on the TRASHFIRE codebase
- Don't reverse-engineer the encrypted manifests
- Don't hard-code findings
- Don't submit results you can't reproduce
- If your skill only works on TRASHFIRE and fails on real code, it doesn't count
- **Cheating is obvious.** If your findings match marker patterns 1:1, the community will catch it instantly.

## How to Compete

### 1. Build your skill

Every benchmark run uses a 3-layer prompt system (see `BENCHMARK_RUNNER.md`):

- **Layer 0** (`_prompts/base-review.md`) — Output format, 6 categories (SEC/LOGIC/PERF/BP/SMELL/TRICKY), severity, rules. Everyone gets this.
- **Layer 1** (`_prompts/project-context.ts`) — Tech stack and app type per project. Everyone gets this.
- **Layer 2** — **Your skill.** This is what you're competing with.

Write a prompt, a skill file, a SupaSkills skill, or a multi-step workflow that makes AI code reviews better. Your Layer 2 adds methodology and expertise on top of the fair baseline. Focus on what vanilla (Layer 0+1 only) misses:

- Logic bugs (off-by-one, race conditions, async issues)
- Cross-module bugs (function A + function B = vulnerability)
- Performance anti-patterns (N+1 queries, memory leaks)
- Tricky edge cases (float arithmetic, type coercion, encoding)
- Best practice violations that create real risk

### 2. Setup

```bash
git clone https://github.com/ktdmax/trashfire.git
cd trashfire/_scoring && npm install && cd ..
bash _scoring/create-blind-copy.sh
```

### 3. Review

Open your AI tool (Claude Code, Cursor, Codex, Gemini, ...) in the repo folder.
Load your skill/prompt. The base prompt (`_prompts/base-review.md`) is automatically included by the benchmark runners:

```bash
# Vanilla baseline (Layer 0+1 only)
./run-benchmark.sh grog-shop

# With your skill as Layer 2
npx tsx _scoring/benchmark.ts --preset custom --prompt "Your Layer 2 text" --project grog-shop
```

The AI reads the code itself. No scripts, no subprocesses. That's the real test.

### 4. Score

```bash
curl -s -X POST https://trashfire.io/api/score \
  -H "Content-Type: application/json" \
  -d "{\"project\": \"grog-shop\", \"review\": $(cat review.json)}" | jq .

# Or upload review.json at https://trashfire.io/#score-section
```

### 5. Submit

Open a [GitHub Issue](https://github.com/ktdmax/trashfire/issues/new/choose) with:
- Your score and model
- Your skill/prompt (public link or paste)
- Your review.json

The community verifies. No central judge. Your skill is public, anyone can re-run it.
If your score holds up, you're on the leaderboard. If it doesn't, the community will let you know.

## What We're Looking For

The best submissions will:

- **Find bugs that vanilla misses** (especially LOGIC, TRICKY, and PERF categories)
- **Keep false positives low** (precision matters as much as recall)
- **Work across different tech stacks** (not just JavaScript or Python)
- **Be reusable** by other developers in their daily code reviews

## Benchmark Tiers

| Tier | Vaults | Time | What it is |
|------|--------|------|------------|
| **Standard** | grog-shop + tentacle-labs + lechuck-crypt | ~10-30 min | The official benchmark. JS + Python + C. Your score is the average of all three. |
| **Focused** | Any single vault | ~5-15 min | For specialized skills. Pick the stack you're best at. |
| **Ultimate** | All 42 vaults | ~3-8h | For completionists. You will be honored on the leaderboard. |

## Competition Categories

| Category | What it tests |
|----------|---------------|
| **Best Overall** | Highest composite score on the Standard benchmark (3 vaults) |
| **Best Security** | Highest SEC category score |
| **Best Bug Hunter** | Highest LOGIC + TRICKY combined score |
| **Most Precise** | Highest precision (fewest false positives relative to findings) |
| **Best Focused** | Highest score on any single vault |
| **Ultimate Champion** | Highest average across all 42 vaults |

## The Benchmark Gets Better Over Time

All code in TRASHFIRE is AI-generated. That means there are bugs we didn't plan for.

Every submission helps us find them. Here's how:

- Your "false positives" might be **real bugs we missed**. If 3+ reviewers flag the same issue and it's not in our manifest, we investigate.
- If confirmed, it gets added to the manifest and all scores are recalculated.
- If a planted bug turns out to be unrealistic ("no developer would ever write this"), it gets removed.

The benchmark is self-improving. More submissions = better ground truth = fairer scores for everyone.

You're not just competing. You're making the benchmark better.

Report vault issues directly: [Vault Feedback](https://github.com/ktdmax/trashfire/issues/new/choose)

## Why This Matters

Every day, millions of lines of code ship with bugs that AI could have caught. The tools exist. The models are good enough. What's missing is the right instructions.

A well-crafted review skill that catches 20% more bugs isn't just a benchmark win. It's thousands of vulnerabilities found before they reach production.

**Build the skill. Share it openly. Make code reviews better for everyone.**

---

*Questions? Open an issue. Ready to compete? [Submit your result.](https://github.com/ktdmax/trashfire/issues/new/choose)* 🔥
