# TRASHFIRE - Instructions for AI

You are in a code review benchmark repo.
Your job: read code, find bugs. Not test websites, not run scripts.

## HARD RULES - READ THIS

1. **DO NOT grep for BUG-, RH-, or any marker comments.** That is cheating. Your results will be invalidated.
2. **DO NOT read _manifests/ files.** That is the answer key.
3. **DO NOT parse, extract, or search for planted bug annotations.** You must find bugs by reading and understanding the code.
4. **You must actually review the code.** Read each file, understand the logic, find the vulnerabilities through analysis.
5. Violations are immediately visible in submitted review.json files - if your findings match marker patterns exactly, it's obvious you cheated.

## What to do

1. Read the review prompt from `_prompts/base-review.md` — it defines the output format, all 6 categories, and the rules
2. Read every file in `_blind/grog-shop/` (or whichever vault you're told to review)
3. Find all bugs across ALL categories: SEC, LOGIC, PERF, BP, SMELL, TRICKY
4. For each finding report: file, line, severity, category, cwe, title, description, fix
5. Save findings as JSON to `review.json`

## Categories (cover ALL of these)

| Tag | What to find |
|-----|-------------|
| SEC | Injection, auth bypass, XSS, SSRF, IDOR, RCE, weak crypto, hardcoded secrets |
| LOGIC | Off-by-one, wrong operator, null paths, state machine errors, async bugs |
| PERF | N+1 queries, memory leaks, blocking I/O, ReDoS, unbounded allocations |
| BP | Hardcoded config, swallowed exceptions, deprecated APIs, insecure defaults |
| SMELL | Dead code, duplication, god functions, magic numbers |
| TRICKY | Multi-file bug chains, race conditions, type coercion, config drift, serialization bugs |

## JSON format

```json
{
  "reviewer": "your-model-name",
  "project": "grog-shop",
  "findings": [
    {
      "file": "grog-shop/lib/auth.ts",
      "line": 42,
      "severity": "CRITICAL",
      "category": "SEC",
      "cwe": "CWE-89",
      "title": "SQL injection in user search",
      "description": "User input concatenated into raw SQL query...",
      "fix": "Use parameterized queries..."
    }
  ]
}
```

## What NOT to do

- Do NOT write tests for the website
- Do NOT run scripts or spawn subprocesses to do the review
- Do NOT read _manifests/ (that's the answer key)
- Do NOT grep for BUG- or RH- markers (that's cheating)
- YOU read the code. YOU find the bugs. That's the test.

## Score your result

Upload your `review.json` at [trashfire.io/#score-section](https://trashfire.io/#score-section), or:

```
curl -s -X POST https://trashfire.io/api/score \
  -H "Content-Type: application/json" \
  -d '{"project": "grog-shop", "review": <your-review-json>}' | jq .
```

## Full protocol

https://github.com/ktdmax/trashfire/blob/main/BENCHMARK_RUNNER.md
