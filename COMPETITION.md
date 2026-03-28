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

No gaming the benchmark.

- Don't train on the TRASHFIRE codebase
- Don't reverse-engineer the encrypted manifests
- Don't hard-code findings
- Don't submit results you can't reproduce
- If your skill only works on TRASHFIRE and fails on real code, it doesn't count

## How to Compete

### 1. Build your skill

Write a prompt, a skill file, a SupaSkills skill, or a multi-step workflow that makes AI code reviews better. Focus on what vanilla prompts miss:

- Logic bugs (off-by-one, race conditions, async issues)
- Cross-module bugs (function A + function B = vulnerability)
- Performance anti-patterns (N+1 queries, memory leaks)
- Tricky edge cases (float arithmetic, type coercion, encoding)
- Best practice violations that create real risk

### 2. Run the benchmark

```bash
git clone https://github.com/ktdmax/trashfire.git
cd trashfire
cd _scoring && npm install && cd ..
bash _scoring/create-blind-copy.sh

# Run with your skill/prompt
bash run-benchmark.sh grog-shop "Your prompt here"
```

Or use any AI tool (Claude Code, Codex, Gemini, etc.) with the standardized test protocol in [BENCHMARK.md](BENCHMARK.md).

### 3. Submit your results

Open a PR or issue with:
- Your skill/prompt (public link or inline)
- The `result.json` from your run
- Which model you used
- Any notes on your approach

## What We're Looking For

The best submissions will:

- **Find bugs that vanilla misses** (especially LOGIC, TRICKY, and PERF categories)
- **Keep false positives low** (precision matters as much as recall)
- **Work across different tech stacks** (not just JavaScript or Python)
- **Be reusable** by other developers in their daily code reviews

## Categories

You can compete in any or all:

| Category | What it tests |
|----------|---------------|
| **Best Overall Score** | Highest composite score on the full benchmark |
| **Best Security** | Highest SEC category score |
| **Best Bug Hunter** | Highest LOGIC + TRICKY combined score |
| **Most Precise** | Highest precision (fewest false positives relative to findings) |
| **Best Multi-Stack** | Highest average score across 5+ different tech stacks |

## Why This Matters

Every day, millions of lines of code ship with bugs that AI could have caught. The tools exist. The models are good enough. What's missing is the right instructions.

A well-crafted review prompt that catches 20% more bugs isn't just a benchmark win. It's thousands of vulnerabilities found before they reach production. It's fewer breaches, fewer exploits, fewer "we regret to inform you" emails.

**Build the skill. Share it openly. Make code reviews better for everyone.**

---

*Questions? Open an issue. Ready to compete? Open a PR.* 🔥
