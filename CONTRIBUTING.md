# Contributing to TRASHFIRE

Thanks for your interest in the AI code review benchmark!

## Ways to Contribute

### 1. Submit Benchmark Runs

The most valuable contribution is running the benchmark with different models, prompts, and skill configurations.

```bash
# Run with your setup
npx tsx _scoring/benchmark.ts --preset custom \
  --prompt "Your prompt here" \
  --project grog-shop \
  --model your-model-id \
  --tag "your-name" \
  --notes "What makes this run interesting"

# Results are saved to _results/<run-id>/
```

Submit a PR with your `_results/<run-id>/result.json` and we'll add it to the leaderboard.

### 2. Add New Projects

Want to add project #43? Here's how:

1. **Pick a LucasArts adventure game reference** for the name
2. **Choose a tech stack** not already covered (see CLAUDE.md for the full list)
3. **Write realistic application code** (8-20 files, 80-300 lines each)
4. **Plant exactly 100 issues** following the distribution in CLAUDE.md
5. **Add 5-10 red herrings** (code that looks vulnerable but is safe)
6. **Mark all issues** with `// BUG-XXXX:` comments (see marking convention)
7. **Generate and encrypt the manifest** using the scoring tools
8. Submit a PR

### 3. Improve Scoring

The scoring algorithm can always be better:
- Improve the matching algorithm (file + line + semantic similarity)
- Add support for new review output formats
- Calibrate difficulty tier multipliers based on empirical data
- Improve category auto-detection from bug descriptions

### 4. Report Issues

Found a bug in the benchmark itself? (Not in the intentionally vulnerable code!)
- Scoring engine not working correctly
- False positive/negative in the matching
- Missing file types in the marker stripper
- Documentation errors

## Development Setup

```bash
git clone https://github.com/YOUR_USER/trashfire.git
cd trashfire

# Install scoring tools
cd _scoring && npm install && cd ..

# Generate blind testing copy (strips BUG markers)
bash _scoring/create-blind-copy.sh

# Run a test benchmark
npx tsx _scoring/benchmark.ts --preset vanilla --project grog-shop

# Regenerate leaderboard
npx tsx _scoring/leaderboard.ts --format md --out LEADERBOARD.md
```

## Bug Marking Convention

Every planted issue gets an inline comment:

```
// BUG-0042: SQL injection via string interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 2)
```

Red herrings get:

```
// RH-003: Looks like XSS but input is sanitized by DOMPurify above
```

Use the appropriate comment syntax for the language (`//`, `#`, `--`, `/* */`).

## Code of Conduct

Be kind. This project is about improving AI tools, not about shaming them. Every model has strengths and weaknesses — the goal is to measure and improve, not to dunk.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
