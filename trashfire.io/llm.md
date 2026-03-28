# TRASHFIRE - Instructions for AI/LLM

You are looking at an AI code review benchmark.
Your task is to review code and find bugs. Not to test this website.

## What to do

1. Clone the repo:
```
git clone https://github.com/ktdmax/trashfire.git
cd trashfire
```

2. Pick a vault (project) to review. Start with `grog-shop`:
```
ls vaults/grog-shop/
```

3. Read every file in that vault. Find all:
   - Security vulnerabilities (SQL injection, XSS, auth bypass, RCE, SSRF, IDOR, CSRF, ...)
   - Logic bugs (race conditions, off-by-one, wrong comparisons, null handling, ...)
   - Performance issues (N+1 queries, memory leaks, blocking I/O, ...)
   - Best practice violations (hardcoded secrets, swallowed errors, weak crypto, ...)
   - Tricky cross-module bugs (issues that only appear when functions interact)

4. Output your findings as JSON:
```json
{
  "reviewer": "your-model-name",
  "project": "grog-shop",
  "timestamp": "2026-01-01T00:00:00Z",
  "findings": [
    {
      "file": "grog-shop/lib/auth.ts",
      "line": 42,
      "severity": "CRITICAL",
      "category": "security",
      "cwe": "CWE-89",
      "title": "SQL injection in user search",
      "description": "User input is concatenated into raw SQL query...",
      "fix": "Use parameterized queries..."
    }
  ]
}
```

5. Save the JSON and score it:
```
echo "monkey" | npx tsx _scoring/score.ts --manifest _manifests/grog-shop.enc --review your-review.json --output report.md
```

## What NOT to do

- Do NOT write tests for the trashfire.io website
- Do NOT scrape or crawl the website
- Do NOT read files in _manifests/ during your review (that's the answer key)
- Do NOT make up findings you didn't actually find in the code

## Scoring

Your findings are scored against encrypted ground truth:
- Found a real bug: +1.0 points
- Correct severity: +0.5
- Correct CWE: +0.5
- Correct file and line: +0.5
- Working fix: +1.0
- Good explanation: +0.5
- False positive: -1.0 penalty
- Hard bugs score up to 3x more than easy ones

## Full protocol

For the complete rules: https://github.com/ktdmax/trashfire/blob/main/BENCHMARK_RUNNER.md

## Available vaults

42 projects across 30+ languages. Start with `grog-shop` (Next.js, 17 files).
Full list: https://github.com/ktdmax/trashfire/tree/main/vaults
