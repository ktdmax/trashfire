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

1. Read every file in `vaults/grog-shop/` (or whichever vault you're told to review)
2. Find all bugs by actually understanding the code: security, logic, performance, best practices, tricky cross-module issues
3. For each finding report: file, line, severity, category, cwe, title, description, fix
4. Save findings as JSON to `review.json`

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
      "category": "security",
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
- YOU read the code. YOU find the bugs. That's the test.

## Score your result

```
echo "monkey" | npx tsx _scoring/score.ts --manifest _manifests/grog-shop.enc --review review.json --output report.md
```

## Full protocol

https://github.com/ktdmax/trashfire/blob/main/BENCHMARK_RUNNER.md
