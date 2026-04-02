/**
 * project-context.ts — Layer 1: Per-project context for benchmark prompts
 *
 * Provides tech stack and app type info that a real auditor would receive
 * as part of the engagement scope. No focus areas (those hint at bug types).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

// ─── Project Metadata (from CLAUDE.md tech stack table) ─────────────────────

interface ProjectMeta {
  stack: string;
  type: string;
  languages: string;
}

const PROJECT_META: Record<string, ProjectMeta> = {
  // Batch 1
  "grog-shop": {
    stack: "Next.js 15, Prisma, NextAuth, Stripe",
    type: "E-commerce platform",
    languages: "TypeScript, JavaScript",
  },
  "tentacle-labs": {
    stack: "Flask, SQLAlchemy, SQLite, manual JWT",
    type: "REST API service",
    languages: "Python",
  },
  "scumm-bar": {
    stack: "Express.js, MongoDB/Mongoose, express-session",
    type: "Web application with NoSQL backend",
    languages: "JavaScript",
  },
  "manny-travel": {
    stack: "React, Express, PostgreSQL (pg), JWT",
    type: "Travel booking platform",
    languages: "JavaScript, TypeScript",
  },
  "sam-max-cases": {
    stack: "Django 5, Django REST Framework, PostgreSQL, Redis",
    type: "Case management API",
    languages: "Python",
  },
  "full-throttle": {
    stack: "Go 1.22, chi router, Docker, Kubernetes",
    type: "Containerized microservice with infrastructure configs",
    languages: "Go, YAML, Dockerfile",
  },
  "loom-weaver": {
    stack: "Vanilla JS/HTML/CSS, fetch API",
    type: "Client-side web application",
    languages: "JavaScript, HTML, CSS",
  },
  "zak-mckracken": {
    stack: "PHP 8, Python, JavaScript, MySQL",
    type: "Mixed-language legacy application",
    languages: "PHP, Python, JavaScript",
  },
  // Batch 2
  "monkey-wrench": {
    stack: "Ruby on Rails 7.1, PostgreSQL, Devise, Sidekiq",
    type: "Web application with background jobs",
    languages: "Ruby, ERB",
  },
  "day-of-the-tentacle": {
    stack: "Elixir 1.16, Phoenix 1.7, LiveView, Ecto",
    type: "Real-time web application",
    languages: "Elixir",
  },
  "indy-fortune": {
    stack: "Spring Boot 3.2, Java 21, Spring Security, JPA",
    type: "Enterprise web application",
    languages: "Java",
  },
  "wally-b-feed": {
    stack: "Spring Boot 3.2, Kotlin 1.9, WebFlux, R2DBC",
    type: "Reactive feed service",
    languages: "Kotlin",
  },
  "guybrush-ledger": {
    stack: "Rust 1.77, Actix-web 4, SQLx, PostgreSQL",
    type: "Financial ledger service",
    languages: "Rust",
  },
  "elaine-marley-mesh": {
    stack: "Rust 1.77, Axum, Tokio, Tower, Redis",
    type: "Service mesh component",
    languages: "Rust",
  },
  // Batch 3
  "lechuck-crypt": {
    stack: "C17, OpenSSL 3.x, CMake, POSIX",
    type: "Cryptographic library",
    languages: "C",
  },
  "murrayd-signal": {
    stack: "C++20, Boost.Asio, nlohmann/json, SQLite",
    type: "Signal processing service",
    languages: "C++",
  },
  "purcell-vault": {
    stack: "C# 12, .NET 8, ASP.NET Core, Entity Framework Core",
    type: "Secrets management service",
    languages: "C#",
  },
  "voodoo-queen": {
    stack: "Swift 5.9, Vapor 4, Fluent, PostgreSQL, JWT",
    type: "Healthcare API",
    languages: "Swift",
  },
  "stan-salesman": {
    stack: "Kotlin 1.9, Ktor 2.3, Exposed, H2/PostgreSQL",
    type: "Sales management platform",
    languages: "Kotlin",
  },
  "fate-of-atlantis": {
    stack: "Scala 3, Play 3.0, Slick, Akka Streams",
    type: "Streaming data platform",
    languages: "Scala",
  },
  "melee-island-analytics": {
    stack: "R 4.3, Shiny, Plumber, DBI, RSQLite",
    type: "Analytics dashboard with API",
    languages: "R",
  },
  // Batch 4
  "woodtick-pipeline": {
    stack: "Python 3.12, Airflow 2.8, Pandas, MinIO",
    type: "Data pipeline orchestrator",
    languages: "Python",
  },
  "brink-deployer": {
    stack: "Terraform 1.7, AWS CDK (TypeScript), GitHub Actions",
    type: "Infrastructure-as-code deployment system",
    languages: "HCL, TypeScript, YAML",
  },
  "dig-site-graphql": {
    stack: "Node.js 20, Apollo Server 4, TypeORM, PostgreSQL",
    type: "GraphQL API",
    languages: "TypeScript",
  },
  "bone-song-rpc": {
    stack: "Go 1.22, gRPC, Protobuf, GORM, PostgreSQL",
    type: "gRPC microservice",
    languages: "Go, Protobuf",
  },
  "phatt-island-chat": {
    stack: "Node.js 20, Socket.IO 4, Redis, MongoDB",
    type: "Real-time chat application",
    languages: "JavaScript, TypeScript",
  },
  "largo-lagrande-lambda": {
    stack: "AWS SAM, Python 3.12 Lambda, DynamoDB, Cognito",
    type: "Serverless application",
    languages: "Python, YAML",
  },
  "governor-phatt-mobile": {
    stack: "React Native 0.73, Expo, AsyncStorage, Axios",
    type: "Mobile application",
    languages: "TypeScript, JavaScript",
  },
  // Batch 5
  "herman-toothrot-vue": {
    stack: "Vue 3, Vite, Pinia, Supabase",
    type: "Frontend application with Supabase backend",
    languages: "TypeScript, Vue",
  },
  "carla-svelte": {
    stack: "SvelteKit 2, Drizzle ORM, SQLite, Lucia Auth",
    type: "Full-stack web application",
    languages: "TypeScript, Svelte",
  },
  "ozzie-mandrill-ml": {
    stack: "Python 3.12, FastAPI, scikit-learn, MLflow",
    type: "Machine learning API service",
    languages: "Python",
  },
  "wally-feeds-flutter": {
    stack: "Flutter 3.19, Dart, Riverpod, Hive, Firebase",
    type: "Cross-platform mobile app",
    languages: "Dart",
  },
  "spiffy-anchor": {
    stack: "Solidity 0.8, Hardhat, Ethers.js, OpenZeppelin",
    type: "Smart contract system",
    languages: "Solidity, JavaScript",
  },
  "captain-dread-pipe": {
    stack: "Julia 1.10, Genie.jl, DataFrames.jl, SQLite",
    type: "Data processing web service",
    languages: "Julia",
  },
  "stan-glass-store": {
    stack: "PHP 8.3, Laravel 11, Eloquent, MySQL, Livewire",
    type: "Online store",
    languages: "PHP, Blade",
  },
  // Batch 6
  "jojo-the-monkey": {
    stack: "Deno 1.40, Fresh 1.6, Deno KV, Preact",
    type: "Edge-deployed web application",
    languages: "TypeScript",
  },
  "griswold-locksmith": {
    stack: "Python 3.12, Typer, Rich, Cryptography, HTTPX",
    type: "CLI security tool",
    languages: "Python",
  },
  "bob-the-ghost": {
    stack: "Haskell (GHC 9.8), Servant, Persistent, SQLite",
    type: "Type-safe API service",
    languages: "Haskell",
  },
  "porcelain-pirates": {
    stack: "Perl 5.38, Mojolicious, DBI, MySQL",
    type: "Web application with image processing",
    languages: "Perl",
  },
  "pegbiter-monitor": {
    stack: "Zig 0.12, C interop, custom HTTP, SQLite",
    type: "System monitoring service",
    languages: "Zig, C",
  },
  "otis-escape-room": {
    stack: "Python 3.12, Litestar 2.x, SQLAlchemy 2.0, Stripe",
    type: "Booking and payment platform",
    languages: "Python",
  },
  "cobb-dataforge": {
    stack: "Python 3.12, dbt-core 1.7, Snowflake, Great Expectations",
    type: "Data transformation pipeline",
    languages: "Python, SQL, Jinja2",
  },
};

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Returns a short project context block (~50-70 tokens).
 * This is Layer 1 of the prompt — the scope document a real auditor receives.
 */
export function getProjectContext(project: string): string {
  const meta = PROJECT_META[project];
  if (!meta) return `## Project: ${project}`;

  return `## Project: ${project}
- Stack: ${meta.stack}
- Type: ${meta.type}
- Languages: ${meta.languages}`;
}

/**
 * Reads base-review.md (Layer 0) from disk.
 */
export function getBasePrompt(): string {
  const promptPath = join(import.meta.dirname ?? ".", "base-review.md");
  return readFileSync(promptPath, "utf-8");
}

/**
 * Builds the complete canonical header: Layer 0 + Layer 1.
 * This is identical for every run of the same project.
 */
export function buildCanonicalHeader(project: string): string {
  const base = getBasePrompt();
  const context = getProjectContext(project);
  return `${base}\n\n${context}`;
}

/**
 * Builds the full review prompt: canonical header + Layer 2 (optional) + file delimiter notice.
 *
 * @param project - Project name
 * @param layer2 - Optional skill/methodology text (empty string for vanilla)
 */
export function buildReviewPrompt(project: string, layer2: string = ""): string {
  const header = buildCanonicalHeader(project);

  const parts = [header];

  if (layer2.trim()) {
    parts.push(`\n\n---\n\n## Additional Review Guidance\n\n${layer2.trim()}`);
  }

  parts.push(`\n\n---\n\nThe codebase follows below. Each file is delimited by === FILE: path ===`);

  return parts.join("");
}

/**
 * List all known project names.
 */
export function listProjects(): string[] {
  return Object.keys(PROJECT_META).sort();
}
