You are reviewing a codebase for bugs and vulnerabilities. Find every issue you can.

## Output — JSON only

```
{
  "findings": [
    {
      "file": "project/path/to/file.ext",
      "line": 42,
      "severity": "HIGH",
      "category": "SEC",
      "cwe": "CWE-89",
      "title": "SQL injection in user lookup",
      "description": "User input concatenated into query without parameterization, allowing arbitrary SQL execution.",
      "fix": "Use parameterized query: db.query('SELECT ... WHERE id = $1', [id])"
    }
  ]
}
```

Output ONLY valid JSON. No markdown fences, no text before or after.

## Categories — cover ALL of these

| Category | Tag | What to find |
|----------|-----|-------------|
| Security | SEC | Injection, auth bypass, XSS, SSRF, IDOR, RCE, path traversal, weak crypto, hardcoded secrets, missing access control |
| Logic | LOGIC | Off-by-one, wrong operator, null/undefined paths, state machine errors, async bugs, error handling gaps |
| Performance | PERF | N+1 queries, memory leaks, blocking I/O, ReDoS, unbounded allocations, missing pagination |
| Best Practice | BP | Hardcoded config, swallowed exceptions, deprecated APIs, insecure defaults, missing validation |
| Code Smell | SMELL | Dead code, duplication, god functions, magic numbers, excessive complexity |
| Tricky | TRICKY | Multi-file bug chains (A→B→C each safe alone), race conditions/TOCTOU, type coercion traps, config drift (dev vs prod), serialization boundary bugs (BigInt→0, Date→string), floating-point in money/business logic, cache poisoning, import-order bugs |

## Severity

- **CRITICAL**: Remote code execution, full auth bypass, data breach
- **HIGH**: Privilege escalation, significant data exposure, injection with impact
- **MEDIUM**: Limited injection, CSRF, information disclosure, logic errors with business impact
- **LOW**: Minor info leak, best practice violation, code smell, hardening gap

## Rules

- Work through EVERY file. Do not skip or skim.
- Report each issue SEPARATELY. Never group multiple issues into one finding.
- Exact file path and line number for each finding.
- CWE ID where applicable, or "none".
- If uncertain whether something is a real issue, report it with LOW severity rather than omitting.
- Trace data across module boundaries — the hardest bugs span multiple files.
