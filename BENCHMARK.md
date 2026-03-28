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

The project is in `projects/grog-shop/` (annotated) or `_blind/grog-shop/` (markers stripped for blind testing).

### Step 2: Give your AI this exact prompt

Copy-paste the prompt below into your AI tool. Replace `[PROJECT]` with the project name.

---

## The Prompt

```
I need you to do a thorough code review of this project. Read every single file.

This is a benchmark test - your findings will be scored against ground truth.
You are competing against other AI models. Be thorough but precise.
False positives cost you points.

For each issue you find, report:
- file: the file path (e.g. "grog-shop/lib/auth.ts")
- line: the line number
- severity: CRITICAL, HIGH, MEDIUM, or LOW
- category: "security", "logic", "performance", "best-practice", or "code-smell"
- cwe: the CWE ID if applicable (e.g. "CWE-89")
- title: short description (one line)
- description: what the issue is and why it matters
- fix: how to fix it

Look for:
- Injection (SQL, NoSQL, command, template)
- Authentication and authorization flaws
- Cryptographic weaknesses
- Data exposure
- Race conditions and concurrency bugs
- Input validation gaps
- Configuration issues
- Logic errors
- Performance anti-patterns
- Cross-module bugs (function A passes data to function B incorrectly)
- Edge cases (empty arrays, negative numbers, unicode, concurrent requests)
- Float arithmetic issues in financial calculations

IMPORTANT: Output your findings as a single JSON object. Nothing else.
No explanation before or after. Just the JSON:

{
  "reviewer": "[YOUR MODEL NAME]",
  "project": "[PROJECT]",
  "timestamp": "[ISO TIMESTAMP]",
  "findings": [
    {
      "file": "[PROJECT]/path/to/file.ext",
      "line": 42,
      "severity": "CRITICAL",
      "category": "security",
      "cwe": "CWE-89",
      "title": "SQL injection in user search",
      "description": "User input is concatenated into SQL query without parameterization...",
      "fix": "Use parameterized queries instead of string concatenation..."
    }
  ]
}

Now read every file in this project and find all issues.
```

### Step 3: Let it read all files and produce the JSON

### Step 4: Save the JSON output as `review.json`

### Step 5: Score it

```bash
cd trashfire
echo "monkey" | npx tsx _scoring/score.ts \
  --manifest _manifests/grog-shop.enc \
  --review review.json \
  --output report.md
```

The report shows your composite score, per-category breakdown, and what was found vs missed.

---

## How To Run In Each Tool

### Claude Code (CLI / Desktop / IDE)

```bash
cd trashfire/_blind
claude -p "$(cat ../BENCHMARK.md | sed -n '/^```$/,/^```$/p' | head -n -1 | tail -n +2)" \
  -c grog-shop \
  --output-format text > review.json
```

Or just open Claude Code in the `_blind/grog-shop/` folder and paste the prompt.

### OpenAI Codex

1. Create a task in codex.openai.com
2. Point it at this repo (or upload the `_blind/grog-shop/` folder)
3. Paste the prompt from above
4. Copy the JSON output

### Google Gemini (AI Studio / Jules)

1. Open AI Studio or Jules
2. Upload the files from `_blind/grog-shop/`
3. Paste the prompt
4. Copy the JSON output

### Any Other Tool

Same process: give it the files, give it the prompt, get the JSON.

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
