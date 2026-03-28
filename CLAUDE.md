# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

TRASHFIRE is an AI code review benchmark suite. It contains **42 intentionally vulnerable mini-applications** (named after LucasArts adventure games), each with **100 planted issues** (security vulnerabilities, logic bugs, performance anti-patterns, best practice violations, code smells, and tricky cross-module bugs). Total: **4,200 issues + ~300 red herrings**.

The goal is to benchmark AI code review skills by scoring how many issues a reviewer finds vs. encrypted ground truth manifests.

**Status:** Phase 1 complete (tooling). Phase 2 in progress (project generation).

## Commands

```bash
# Score a review against encrypted ground truth
npx tsx _scoring/score.ts --manifest _manifests/<project>.enc --review review-output.json

# Encrypt a plaintext manifest
npx tsx _scoring/crypto.ts encrypt --file _manifests/<project>.json

# Decrypt a manifest (to stdout, never to disk in production)
npx tsx _scoring/crypto.ts decrypt --file _manifests/<project>.enc

# Strip BUG markers for blind testing
bash _scoring/strip-markers.sh <project-dir>
bash _scoring/strip-markers.sh <project-dir> --dry-run

# Run a benchmark: review with a skill vs. vanilla
claude --skill security-code-reviewer "Review this codebase for security vulnerabilities. Check every file."
claude "Review this codebase for security vulnerabilities. Check every file."
```

Per-project commands depend on the framework (see tech stack table below).

## Architecture

```
trashfire/
  vaults/            # 42 vulnerable mini-apps (see tech stack below)
  _manifests/          # Encrypted ground truth (.enc files, AES-256-GCM)
  _scoring/            # TypeScript scoring engine, crypto module, strip script
    types.ts           # All TypeScript interfaces and constants
    crypto.ts          # AES-256-GCM encrypt/decrypt with PBKDF2 key derivation
    score.ts           # Composite scoring engine with per-category sub-scores
    strip-markers.sh   # Removes // BUG-XXXX: comments for blind testing
  _md/                 # Research documents and reports
```

Each project is **self-contained**  - its own framework, DB, auth, and dependencies. No shared code between projects.

## Tech Stack Per Project (42 Projects)

### Batch 1: Original 8

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 1 | grog-shop | Next.js 15 + Prisma + NextAuth | E-commerce: payment, cart, user data |
| 2 | tentacle-labs | Flask + SQLAlchemy + SQLite + manual JWT | API: injection, serialization, file handling |
| 3 | scumm-bar | Express.js + MongoDB/Mongoose + sessions | NoSQL injection, race conditions, business logic |
| 4 | manny-travel | React + Express + Postgres (pg) + JWT | Cross-module logic, state management |
| 5 | sam-max-cases | Django 5 + DRF + Postgres + Redis | Permission escalation, cache poisoning, ORM abuse |
| 6 | full-throttle | Go 1.22 + chi + Docker + K8s configs | Infra: Dockerfile, K8s YAML, secrets, RBAC misconfig |
| 7 | loom-weaver | Vanilla JS/HTML/CSS + fetch API | Client-side: DOM XSS, open redirect, prototype pollution |
| 8 | zak-mckracken | PHP 8 + Python + JS mixed + MySQL | Version traps, dependency vulns, mixed legacy |

### Batch 2

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 9 | monkey-wrench | Ruby on Rails 7.1 + Postgres + Devise + Sidekiq | Mass assignment, IDOR, session fixation |
| 10 | day-of-the-tentacle | Elixir 1.16 + Phoenix 1.7 + LiveView + Ecto | WebSocket auth bypass, channel injection |
| 11 | indy-fortune | Spring Boot 3.2 + Java 21 + Spring Security + JPA | SpEL injection, JPQL injection, SSRF |
| 12 | wally-b-feed | Spring Boot 3.2 + Kotlin 1.9 + WebFlux + R2DBC | Reactive stream abuse, R2DBC injection |
| 13 | guybrush-ledger | Rust 1.77 + Actix-web 4 + SQLx + Postgres | Unsafe blocks, integer overflow, TOCTOU |
| 14 | elaine-marley-mesh | Rust 1.77 + Axum + Tokio + Tower + Redis | TLS bypass, memory safety, DoS |

### Batch 3

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 15 | lechuck-crypt | C17 + OpenSSL 3.x + CMake + POSIX | Buffer overflow, use-after-free, format string |
| 16 | murrayd-signal | C++20 + Boost.Asio + nlohmann/json + SQLite | Heap overflow, dangling refs, resource exhaustion |
| 17 | purcell-vault | C# 12 / .NET 8 + ASP.NET Core + EF Core | Insecure crypto, LINQ injection, XXE |
| 18 | voodoo-queen | Swift 5.9 + Vapor 4 + Fluent + Postgres + JWT | JWT algorithm confusion, HIPAA data exposure |
| 19 | stan-salesman | Kotlin 1.9 + Ktor 2.3 + Exposed + H2/Postgres | SSTI, IDOR, exposed H2 console |
| 20 | fate-of-atlantis | Scala 3 + Play 3.0 + Slick + Akka Streams | XML injection, path traversal, ReDoS |
| 21 | melee-island-analytics | R 4.3 + Shiny + Plumber + DBI + RSQLite | eval/parse injection, SQLi, path traversal |

### Batch 4

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 22 | woodtick-pipeline | Python 3.12 + Airflow 2.8 + Pandas + MinIO | Pickle RCE, SSRF, hardcoded creds |
| 23 | brink-deployer | Terraform 1.7 + AWS CDK (TS) + GitHub Actions | IAM *, public S3, unencrypted RDS |
| 24 | dig-site-graphql | Node.js 20 + Apollo Server 4 + TypeORM + Postgres | Query depth attack, N+1, auth bypass |
| 25 | bone-song-rpc | Go 1.22 + gRPC + Protobuf + GORM + Postgres | Missing gRPC auth, protobuf bypass |
| 26 | phatt-island-chat | Node.js 20 + Socket.IO 4 + Redis + MongoDB | WebSocket auth bypass, message injection |
| 27 | largo-lagrande-lambda | AWS SAM + Python 3.12 Lambda + DynamoDB + Cognito | Lambda injection, permissive IAM, SSRF |
| 28 | governor-phatt-mobile | React Native 0.73 + Expo + AsyncStorage + Axios | Insecure storage, cert pinning, deep link hijack |

### Batch 5

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 29 | herman-toothrot-vue | Vue 3 + Vite + Pinia + Supabase | RLS bypass, v-html XSS, prototype pollution |
| 30 | carla-svelte | SvelteKit 2 + Drizzle ORM + SQLite + Lucia Auth | Form CSRF, path traversal, IDOR |
| 31 | ozzie-mandrill-ml | Python 3.12 + FastAPI + scikit-learn + MLflow | Pickle RCE, pandas eval injection |
| 32 | wally-feeds-flutter | Flutter 3.19 + Dart + Riverpod + Hive + Firebase | Hive unencrypted, Firebase rules misconfig |
| 33 | spiffy-anchor | Solidity 0.8 + Hardhat + Ethers.js + OpenZeppelin | Reentrancy, front-running, delegatecall |
| 34 | captain-dread-pipe | Julia 1.10 + Genie.jl + DataFrames.jl + SQLite | Meta.parse/eval injection, path traversal |
| 35 | stan-glass-store | PHP 8.3 + Laravel 11 + Eloquent + MySQL + Livewire | Mass assignment, Blade XSS, race condition |

### Batch 6

| # | Project | Stack | Focus Area |
|---|---------|-------|------------|
| 36 | jojo-the-monkey | Deno 1.40 + Fresh 1.6 + Deno KV + Preact | Prototype pollution, OAuth redirect |
| 37 | griswold-locksmith | Python 3.12 + Typer + Rich + Cryptography + HTTPX | Weak KDF, nonce reuse, TOCTOU |
| 38 | bob-the-ghost | Haskell (GHC 9.8) + Servant + Persistent + SQLite | Open redirect, rawSql injection, timing attack |
| 39 | porcelain-pirates | Perl 5.38 + Mojolicious + DBI + MySQL | Command injection (ImageMagick), ReDoS |
| 40 | pegbiter-monitor | Zig 0.12 + C interop + custom HTTP + SQLite | Buffer overflow, use-after-free, null deref |
| 41 | otis-escape-room | Python 3.12 + Litestar 2.x + SQLAlchemy 2.0 + Stripe | Webhook bypass, double-booking race condition |
| 42 | cobb-dataforge | Python 3.12 + dbt-core 1.7 + Snowflake + Great Expectations | Jinja2 SQLi, secret leakage, macro injection |

## Issue Design Rules

When writing vulnerable code for this benchmark:

1. **Every bug must be exploitable**  - no theoretical-only vulnerabilities
2. **Code must look realistic**  - a senior developer should not spot all bugs on a skim read
3. **Mix obvious and subtle**  - some bugs catch attention, others hide in plain sight
4. **Cross-module bugs are the real test**  - bugs that span 3+ functions/files
5. **Include red herrings** (5-10 per project)  - code that looks vulnerable but is actually safe
6. **All code must parse/compile**  - no broken syntax
7. **Not just security**  - include logic bugs, performance issues, best practice violations, code smells

### Issue Categories (6 categories, 100 issues per project)

| Category | ID | Description | Count/Project |
|----------|----|-------------|---------------|
| Security Vulnerabilities | `SEC` | OWASP Top 10, CWE-mapped, exploitable | ~42 |
| Logic Bugs | `LOGIC` | Off-by-one, wrong operator, state machine, async | ~15 |
| Performance Anti-Patterns | `PERF` | N+1, memory leak, blocking I/O, ReDoS | ~13 |
| Best Practice Violations | `BP` | Error handling, hardcoded config, deprecated APIs | ~10 |
| Code Smells | `SMELL` | Dead code, duplication, god functions, magic numbers | ~8 |
| Tricky / Cross-Module | `TRICKY` | Cross-file chains, edge cases, timing, environment | ~12 |

### Severity Distribution Per Project

```
CRITICAL (CVSS 9-10):     17  → all SEC
HIGH (CVSS 7-8.9):        18  → 15 SEC + 3 LOGIC
MEDIUM (CVSS 4-6.9):      18  → 10 SEC + 4 LOGIC + 4 PERF
LOW (CVSS 0.1-3.9):       12  → 4 SEC + 3 BP + 3 SMELL + 2 PERF
BEST_PRACTICE:             12  → 5 BP + 4 SMELL + 3 PERF
TRICKY:                    13  → distributed across SEC/LOGIC/PERF
RED_HERRING:             5-10  → separate, not counted in the 100
```

### 15 TRICKY Patterns (min 10 per project)

| Pattern | Description |
|---------|-------------|
| TRICKY-CHAIN | Function chain bug: A→B→C, each individually correct |
| TRICKY-EDGE | Edge-case trigger: rare API response, unusual input |
| TRICKY-RACE | Timing / race condition (TOCTOU) |
| TRICKY-ENV | Environment-dependent: works in dev, breaks in prod |
| TRICKY-COERCE | Type coercion trap (JS `==`, PHP type juggling) |
| TRICKY-IMPORT | Import / init order bug (circular deps) |
| TRICKY-CONFIG | Configuration drift (.env vs Docker vs k8s) |
| TRICKY-DEPVER | Dependency version conflict |
| TRICKY-LOCALE | Locale / encoding trap (Turkish I, UTF-8/Latin-1) |
| TRICKY-BIZLOGIC | Exploitable business logic (spec-conform but exploitable) |
| TRICKY-PROTO | Prototype / inheritance pollution |
| TRICKY-CACHE | Cache poisoning / staleness |
| TRICKY-SERIAL | Serialization boundary (BigInt→0, Date→string) |
| TRICKY-FLOAT | Floating point arithmetic in business logic |
| TRICKY-REGEX | Regex state / statefulness (global flag lastIndex) |

### Issue Marking Convention

- Inline comments: `// BUG-XXXX: description` (stripped for blind testing via `strip-markers.sh`)
- IDs: BUG-0001 through BUG-0100 per project (project-scoped)
- Comments include CWE and CVSS reference
- Red herrings: `// RH-XXX: description`
- Each project gets an encrypted manifest in `_manifests/<project>.enc`

## Scoring System

### Per-Issue (max 4.0 raw points)

| Component | Points |
|-----------|--------|
| Detection (found it) | 1.0 |
| Correct severity | 0.5 |
| Correct CWE/category | 0.5 |
| Accurate location (file+line) | 0.5 |
| Working fix | 1.0 |
| Explanation quality | 0.5 |

### Difficulty Multipliers

| Tier | Label | Multiplier |
|------|-------|-----------|
| 1 | Obvious | ×1.0 |
| 2 | Standard | ×1.25 |
| 3 | Moderate | ×1.5 |
| 4 | Hard | ×2.0 |
| 5 | Expert | ×3.0 |

### Composite Score Formula

```
CompositeScore = (
    0.35 × SEC_score +
    0.20 × LOGIC_score +
    0.10 × PERF_score +
    0.05 × BP_score +
    0.05 × SMELL_score +
    0.25 × TRICKY_score
) − FP_penalty

Penalties: -1.0 per false positive, -2.0 per flagged red herring
```

### Encrypted Solutions (Anti-Cheating)

- Manifests encrypted with AES-256-GCM, PBKDF2-HMAC-SHA512 (600k iterations)
- Binary format: `TFBM` magic + salt + IV + auth tag + ciphertext
- Passphrase provided at scoring time only (never in repo)
- `// BUG-XXXX:` comments stripped for blind testing
- Snippet hashes in manifest for tamper detection

## Benchmark Runner

Before running any benchmark, read `BENCHMARK_RUNNER.md` in full.
That file defines the protocol. This section is just the entry point.

### Running a test

```bash
# Vanilla (no skill)
run benchmark vanilla --project grog-shop

# With one Supaskills skill
run benchmark --skill supaskills:security-code-reviewer --project grog-shop

# With a local skill file
run benchmark --skill ./my-skill.md --project grog-shop

# With multiple skills combined
run benchmark --skills supaskills:security-code-reviewer,supaskills:vuln-hunter --project grog-shop

# All projects, vanilla
run benchmark --all

# Compare all runs for a project
compare runs --project grog-shop

# Prepare a leaderboard submission
submit result --run <run-id> --project grog-shop
```

### Fair play rules (enforced always)

1. Every run for the same project uses the same canonical prompt - built once,
   stored in `_runs/<project>/canonical_prompt.txt`, never modified between runs.
2. BUG-XXX marker comments are stripped from source before the prompt is built.
   The reviewer never sees them.
3. Manifests in `_manifests/` are never read during the review phase.
4. Skills are loaded verbatim - not summarised, not modified.
5. Vanilla runs have zero system context additions.
6. A run that violated any of these rules cannot be submitted to the leaderboard.

## MCP Integration

- **SupaSkills** for security expertise: `claude mcp add supaskills --transport http -H "Authorization: Bearer YOUR_KEY" -- https://www.supaskills.ai/mcp`
- **Context7** for framework docs (active): `claude mcp add context7 -- npx -y @upstash/context7-mcp@latest` - append `use context7` to prompts when writing framework-specific code to pull current docs and ensure vulnerability patterns match real framework behavior
