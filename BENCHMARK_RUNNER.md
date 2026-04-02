# BENCHMARK_RUNNER.md

Instructions for executing TRASHFIRE benchmark runs.
Read this file completely before running any benchmark.

---

## HARD RULES

These are non-negotiable. Violations invalidate your result.

1. **DO NOT grep, search, or parse BUG-XXX / RH-XXX marker comments.** That is cheating. Find bugs by reading and understanding the code.
2. **DO NOT read _manifests/ files.** That is the encrypted answer key.
3. **DO NOT use the vaults/ folder directly for review.** The source files contain bug marker comments. Use the blind copy (_blind/) or strip markers first.
4. **You must actually review the code.** Read each file, understand the logic, find vulnerabilities through analysis - not pattern matching on annotations.
5. **Cheating is obvious.** If your findings map 1:1 to marker comments, it will be caught immediately by the community.

---

## What a fair run means

Every model, every skill, every run must receive **identical input**.
The only variable that changes between runs is the system context (vanilla vs. skill-loaded).
If the input changes, the result is not comparable. Do not improvise.

---

## Prompt architecture — three layers

Every benchmark prompt is composed from exactly three layers.
Layer 0 and Layer 1 are identical across all runs for the same project.
Layer 2 is the experimental variable — it is what the benchmark measures.

```
┌──────────────────────────────────────────────────────┐
│ LAYER 0: Base Review Prompt  (always, identical)     │
│ File: _prompts/base-review.md  (~500 tokens)         │
│ Contains: JSON output schema, 6 categories,          │
│ severity levels, behavioral rules                    │
├──────────────────────────────────────────────────────┤
│ LAYER 1: Project Context  (always, per-project)      │
│ Source: _prompts/project-context.ts lookup table      │
│ Contains: tech stack, app type, languages (~70 tok)  │
├──────────────────────────────────────────────────────┤
│ LAYER 2: Skill / Methodology  (VARIABLE)             │
│ Vanilla run:  empty — no Layer 2                     │
│ Skill run:    loaded Supaskills or local .md files   │
│ Preset run:   short methodology addition             │
└──────────────────────────────────────────────────────┘
```

| Layer | Contents | Varies between runs? | Fair? |
|-------|----------|---------------------|-------|
| 0 — Base | Output format, categories, severity, rules | Never | Yes — defines the scoring contract |
| 1 — Context | Tech stack, app type, languages | Per project, not per run | Yes — real auditors receive a scope document |
| 2 — Skill | Methodology, expertise, focus | **Yes — this is the benchmark variable** | N/A — this is what we measure |

### What Layer 0 contains (and why it is NOT cheating)

Layer 0 tells the reviewer:
- The JSON output format the scorer expects (without this, findings cannot be scored)
- The 6 issue categories: SEC, LOGIC, PERF, BP, SMELL, TRICKY (this is scope, not answers)
- Severity definitions (CRITICAL / HIGH / MEDIUM / LOW)
- Rules: report individually, be precise, trace cross-module flows

It does NOT contain: bug counts, difficulty distribution, specific planted patterns, or manifest data.

### What Layer 1 contains (and why it is NOT cheating)

Layer 1 tells the reviewer:
- The tech stack (e.g., "Next.js 15, Prisma, NextAuth, Stripe")
- The application type (e.g., "E-commerce platform")
- The languages used (e.g., "TypeScript, JavaScript")

This is information any auditor can derive from `package.json` / `go.mod` / file extensions.
It does NOT contain: focus areas (those hint at planted bug types) or any manifest data.

---

## The canonical prompt

The canonical prompt is Layer 0 + Layer 1 + source files.
It is built once per project, deterministically, and never changes between runs.

### How to build it

```
1. Load Layer 0: read _prompts/base-review.md verbatim
2. Load Layer 1: call getProjectContext(project) from _prompts/project-context.ts
3. Combine: Layer 0 + "\n\n" + Layer 1 + "\n\n---\n\n" + file delimiter notice
4. Collect all source files from vaults/<project>/ recursively
5. Sort them alphabetically by relative path
6. Exclude: node_modules/, vendor/, __pycache__/, .git/, *.lock, *.sum, dist/, build/
7. For each file: strip all inline comments matching // BUG-\w+: or # BUG-\w+:
   (these are the ground-truth markers — the reviewer must not see them)
8. Concatenate files in this format:

=== FILE: <relative/path/to/file.ext> ===
<file contents with BUG comments stripped>

9. Save the result to _runs/<project>/canonical_prompt.txt
10. Save SHA256 of the file to _runs/<project>/canonical_prompt.sha256
    (used later to verify integrity of any submitted result)
```

### Single source of truth

Do not copy the base prompt inline. Always read `_prompts/base-review.md` at build time.
If the base prompt changes, regenerate canonical prompts and invalidate all prior runs.

---

## Run modes

### Vanilla run

Layer 0 + Layer 1 only. No Layer 2 (no skills, no extra methodology).
This is the baseline — it tests raw model capability with fair instructions.

```bash
run benchmark vanilla --project <project-name>
```

What Claude Code does:
1. Build or load the canonical prompt from `_runs/<project>/canonical_prompt.txt`
2. Run the review using the prompt alone, with zero system prompt additions
3. Save raw output to `_runs/<project>/results/vanilla_<timestamp>.md`
4. Score: `npx tsx _scoring/score.ts --manifest _manifests/<project>.json --output ...`
5. Save score to `_runs/<project>/results/vanilla_<timestamp>.score.json`
6. Update the project leaderboard (see leaderboard section)

### Skill run

Layer 0 + Layer 1 + Layer 2 (loaded skills as system context).
The canonical prompt (Layer 0+1) is identical to vanilla — only Layer 2 differs.

```bash
run benchmark --skill supaskills:<slug> --project <project-name>
run benchmark --skill ./my-skill.md --project <project-name>
run benchmark --skills supaskills:<slug1>,supaskills:<slug2> --project <project-name>
run benchmark --skills supaskills:<slug>,./local-skill.md --project <project-name>
```

What Claude Code does:
1. Resolve each skill source:
   - `supaskills:<slug>` — call the Supaskills MCP tool `get_skill` with that slug
   - `./path/to/skill.md` — read the local file verbatim
2. Concatenate all loaded skills in the order specified, separated by `\n\n---\n\n`
3. This combined text becomes the system context — do not modify it
4. Build or load the canonical prompt — identical to vanilla, do not change it
5. Run the review with skill text as system context, canonical prompt as user input
6. Save skill metadata to `_runs/<project>/results/<run-id>.skill.json`:
   ```json
   {
     "skills": ["supaskills:security-code-reviewer", "./my-skill.md"],
     "skill_sources": {
       "supaskills:security-code-reviewer": "<full skill text>",
       "./my-skill.md": "<full file text>"
     }
   }
   ```
7. Save raw output to `_runs/<project>/results/<run-id>.md`
8. Score it against the manifest
9. Save score to `_runs/<project>/results/<run-id>.score.json`
10. Update the project leaderboard

### Run ID format

```
<mode>_<skill-slug-or-none>_<YYYY-MM-DD_HH-MM>
```

Examples:
```
vanilla_2026-03-28_14-30
skill_security-code-reviewer_2026-03-28_14-45
skill_security-code-reviewer+vuln-hunter_2026-03-28_15-00
```

---

## What Claude Code must NOT do during a benchmark run

These rules preserve fairness. Do not break them for any reason.

- Do not read `_manifests/` during the review phase. Manifests are only for the scorer.
- Do not add context that is not in the canonical prompt or the loaded skill.
  No extra hints. No "I notice this is a benchmark."
- Do not modify the canonical prompt between runs for the same project.
  If the prompt must change, regenerate it and invalidate all previous runs for that project.
- Do not load skills that were not explicitly requested by the user.
- Do not combine vanilla and skill output into the same result file.
- Do not run the scorer before the review is complete.

---

## Per-project leaderboard

### Core concept

The TRASHFIRE leaderboard works per project, not globally.
You can win on a single project. You do not need to run all 42.

Each of the 42 projects in `vaults/` has its own independent leaderboard.
The leaderboard tracks the top score ever achieved on that project,
plus the full run history and the official vanilla baseline.

A run claims the top spot when its weighted score is strictly higher
than the current record for that project.

An unclaimed project (no community runs yet) is open for anyone to take.

### Project leaderboard file

After every scored run, Claude Code updates or creates:

```
_leaderboard/<project>/leaderboard.json
```

Format:
```json
{
  "project": "<project-name>",
  "canonical_prompt_sha256": "<sha256>",
  "record": {
    "score": 73.1,
    "found": 12,
    "total": 15,
    "false_positives": 2,
    "run_id": "skill_security-code-reviewer_2026-03-28_14-45",
    "model": "gemini-2.5-pro",
    "skills": ["supaskills:security-code-reviewer"],
    "submitted_by": "ktdmax",
    "date": "2026-03-28"
  },
  "vanilla_baseline": {
    "score": 20.1,
    "found": 4,
    "total": 15,
    "false_positives": 1,
    "run_id": "vanilla_2026-03-28_14-30",
    "model": "claude-sonnet",
    "date": "2026-03-28"
  },
  "history": [
    {
      "score": 20.1,
      "run_id": "vanilla_2026-03-28_14-30",
      "model": "claude-sonnet",
      "skills": [],
      "date": "2026-03-28"
    },
    {
      "score": 73.1,
      "run_id": "skill_security-code-reviewer_2026-03-28_14-45",
      "model": "gemini-2.5-pro",
      "skills": ["supaskills:security-code-reviewer"],
      "date": "2026-03-28"
    }
  ]
}
```

Rules:
- `record` is the single highest score ever achieved on this project
- `vanilla_baseline` is set by the maintainers and is never overwritten by community runs
- `history` is append-only, chronological
- Equal scores do not replace the current record — first to reach a score wins
- A new record only counts if the canonical prompt SHA256 matches the current one

### When a new record is set

Claude Code prints:

```
NEW RECORD — <project>
Previous: <old_score>% (<previous_holder> with <previous_skills>)
New:      <new_score>% (<new_holder> with <new_skills>)
Delta over vanilla baseline: +<Xpp>
```

### Global leaderboard

```
_leaderboard/global.json
```

Rebuilt automatically whenever any project leaderboard changes.
Never edit it directly — it is a read-only aggregation.

```json
{
  "generated": "2026-03-28T15:00:00Z",
  "total_projects": 42,
  "projects_with_records": 3,
  "projects_open": 39,
  "projects": [
    {
      "project": "grog-shop",
      "record_score": 73.1,
      "record_holder": "ktdmax",
      "record_model": "gemini-2.5-pro",
      "record_skills": ["supaskills:security-code-reviewer"],
      "vanilla_baseline": 20.1,
      "improvement": "+53.0pp",
      "date": "2026-03-28"
    },
    {
      "project": "tentacle-labs",
      "record_score": null,
      "record_holder": null,
      "record_skills": [],
      "vanilla_baseline": null,
      "improvement": null,
      "date": null
    }
  ]
}
```

Projects with `null` values have no runs yet. They are fully open.

---

## Leaderboard commands

```bash
# Current leaderboard for one project
leaderboard --project <project-name>

# All 42 projects, one line per project
leaderboard --global

# Only projects with no community run yet (open to claim)
leaderboard --open

# Only projects where no skill has beaten the vanilla baseline yet
leaderboard --unbeaten

# Full run history for one project
leaderboard --history --project <project-name>
```

Output format for `leaderboard --project <project>`:

```
<project> — leaderboard

Vanilla baseline:   20.1%   (4/15 found, 1 FP)  claude-sonnet — 2026-03-28
Community record:   73.1%   (12/15 found, 2 FP)  gemini-2.5-pro + security-code-reviewer — 2026-03-28
Improvement:        +53.0pp over vanilla

Run history (4 runs):
  1   20.1%   vanilla                     claude-sonnet      2026-03-28
  2   45.2%   security-code-reviewer      claude-opus        2026-03-28
  3   58.8%   vuln-hunter                 gpt-4o             2026-03-29
  4   73.1%   security-code-reviewer      gemini-2.5-pro     2026-03-29  RECORD
```

Output format for `leaderboard --global`:

```
TRASHFIRE global leaderboard — 42 projects

Project               Record    Holder          Skills                    vs Vanilla
-------------------------------------------------------------------------------------
grog-shop             73.1%     ktdmax          security-code-reviewer    +53.0pp
tentacle-labs         --        --              --                        --  (open)
scumm-bar             58.8%     user2           vuln-hunter               +31.2pp
...
```

---

## Comparing local runs

```bash
compare runs --project <project-name>
```

Reads all `.score.json` files in `_runs/<project>/results/` and outputs a table:

| Run | Skills | Found | FP | Score | CRITICAL | HIGH | MEDIUM | LOW | TRICKY |
|-----|--------|-------|----|-------|----------|------|--------|-----|--------|
| vanilla | none | 4/15 | 1 | 20.1% | 0% | 10% | 40% | 80% | 0% |
| skill_security-code-reviewer | 1 skill | 12/15 | 2 | 73.1% | 80% | 75% | 100% | 100% | 100% |

Rules:
- Only compare runs from the same project (same canonical prompt SHA256)
- Label every run clearly with what was loaded
- Flag any run with a different SHA256 as not comparable

---

## Submitting a result

```bash
submit result --run <run-id> --project <project-name>
```

Claude Code prepares a submission package at `_submissions/<project>/<run-id>/`:

```
submission.md                 # Human-readable summary (see format below)
<run-id>.md                   # Raw review output
<run-id>.score.json           # Scored result
<run-id>.skill.json           # Full skill text — required for skill runs, omit for vanilla
canonical_prompt.sha256       # Proves the canonical prompt was not modified
```

`submission.md` format:

```markdown
# TRASHFIRE submission — <project>

- Model: <model name and version>
- Date: <YYYY-MM-DD>
- Skills loaded: <list of skill slugs / filenames, or "none">
- Skill description: <one paragraph — what does the skill do, what is its focus?>
- Score: <X>%
- Found: <X>/<total>
- False positives: <X>
- Submitted by: <GitHub username>
```

Rules:
- Skill text is always fully public. Private skills cannot be submitted.
- One submission per run. Do not bundle multiple runs into one PR.
- The canonical prompt SHA256 must match the version in the repo for that project.
- Maintainers re-score every submission independently before accepting.

The user submits the package as a pull request to `ktdmax/trashfire`.

---

## Directory layout

```
trashfire/
  vaults/                             # 42 vulnerable applications (read-only during runs)
    <project>/
  _manifests/                           # Ground truth (read-only during review phase)
    <project>.json
  _scoring/                             # Scoring scripts
    score.ts
  _runs/                                # Local run output (gitignored)
    <project>/
      canonical_prompt.txt
      canonical_prompt.sha256
      results/
        <run-id>.md
        <run-id>.score.json
        <run-id>.skill.json
  _leaderboard/                         # Committed to repo — updated via PR
    global.json
    <project>/
      leaderboard.json
  _submissions/                         # Staged for PR submission
    <project>/
      <run-id>/
        submission.md
        <run-id>.md
        <run-id>.score.json
        <run-id>.skill.json
        canonical_prompt.sha256
```

---

## Quick reference

| Command | What Claude Code does |
|---|---|
| `run benchmark vanilla --project <p>` | Vanilla run, update leaderboard |
| `run benchmark --skill supaskills:<slug> --project <p>` | Load Supaskills skill, run, update leaderboard |
| `run benchmark --skill ./skill.md --project <p>` | Load local skill file, run, update leaderboard |
| `run benchmark --skills supaskills:<a>,supaskills:<b> --project <p>` | Load two skills combined, run |
| `run benchmark --all` | Vanilla run on all 42 projects in sequence |
| `leaderboard --project <p>` | Current leaderboard and history for one project |
| `leaderboard --global` | All 42 projects, current record per project |
| `leaderboard --open` | Projects with no community run yet |
| `leaderboard --unbeaten` | Projects where no skill has beaten vanilla yet |
| `compare runs --project <p>` | Compare all local runs for one project |
| `submit result --run <id> --project <p>` | Prepare submission package for PR |
| `rebuild prompt --project <p>` | Regenerate canonical prompt (invalidates prior runs) |
