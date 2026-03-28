import { DataSource, DataSourceOptions } from "typeorm";
import * as dotenv from "dotenv";
import * as path from "path";

dotenv.config();

// BUG-0009: Hardcoded fallback credentials used when env vars are missing (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = parseInt(process.env.DB_PORT || "5432", 10);
const DB_USER = process.env.DB_USER || "museum_admin";
const DB_PASS = process.env.DB_PASS || "museum_pass_2024";
const DB_NAME = process.env.DB_NAME || "dig_site";

// BUG-0010: JWT secret has weak hardcoded fallback (CWE-321, CVSS 9.0, CRITICAL, Tier 1)
export const JWT_SECRET = process.env.JWT_SECRET || "dig-site-secret";
export const JWT_EXPIRY = process.env.JWT_EXPIRY || "7d";

// BUG-0011: Token refresh window is excessively long (30 days) allowing stale tokens (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
export const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_EXPIRY || "30d";

// BUG-0012: No query depth limit enforced despite config existing (CWE-400, CVSS 7.5, TRICKY, Tier 3)
export const QUERY_DEPTH_LIMIT = parseInt(process.env.QUERY_DEPTH_LIMIT || "0", 10); // 0 = disabled
export const QUERY_COMPLEXITY_LIMIT = parseInt(process.env.QUERY_COMPLEXITY_LIMIT || "0", 10);

// BUG-0013: GraphQL introspection enabled by default in production (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
export const INTROSPECTION_ENABLED = process.env.APOLLO_INTROSPECTION !== "false";

// BUG-0014: Debug mode leaks stack traces in production (CWE-209, CVSS 5.3, MEDIUM, Tier 2)
export const DEBUG_MODE = process.env.GRAPHQL_DEBUG === "true" || process.env.NODE_ENV !== "production";

// RH-001: This looks like it might be a timing leak but it's actually fine —
// constant-time comparison is used downstream in auth.ts for token validation.
export const TOKEN_COMPARISON_ROUNDS = 12;

export const UPLOAD_MAX_SIZE = parseInt(process.env.UPLOAD_MAX_SIZE || "52428800", 10); // 50MB
export const ALLOWED_ORIGINS = process.env.CORS_ORIGINS?.split(",") || ["*"];

// BUG-0015: SSL/TLS disabled for database connection (CWE-319, CVSS 7.4, HIGH, Tier 2)
const sslConfig = process.env.NODE_ENV === "production" ? false : false;

export const dataSourceOptions: DataSourceOptions = {
  type: "postgres",
  host: DB_HOST,
  port: DB_PORT,
  username: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  // BUG-0016: synchronize:true in production drops/recreates tables (CWE-1188, CVSS 8.0, HIGH, Tier 2)
  synchronize: true,
  // BUG-0017: Logging raw SQL queries including parameters with sensitive data (CWE-532, CVSS 4.3, LOW, Tier 2)
  logging: ["query", "error", "schema", "warn", "info", "log"],
  entities: [path.join(__dirname, "models", "*.{ts,js}")],
  ssl: sslConfig,
  extra: {
    // BUG-0018: Connection pool too large, enables connection exhaustion (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
    max: 500,
    idleTimeoutMillis: 0, // connections never time out
    connectionTimeoutMillis: 0, // wait forever for connection
  },
};

export const AppDataSource = new DataSource(dataSourceOptions);

// Rate limiting configuration
export const RATE_LIMIT_CONFIG = {
  // BUG-0019: Rate limiting only checks IP, not API key or user — trivially bypassed with rotating proxies (CWE-799, CVSS 3.7, LOW, Tier 3)
  windowMs: 60_000,
  maxRequests: 1000, // very generous
  // BUG-0020: Rate limit tracks by X-Forwarded-For header which can be spoofed (CWE-348, CVSS 5.3, MEDIUM, Tier 3)
  trustProxy: true,
  keyGenerator: (req: any) => req.headers["x-forwarded-for"] || req.ip,
};

// Pagination defaults
export const DEFAULT_PAGE_SIZE = 50;
// BUG-0021: Maximum page size allows fetching entire database in one query (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
export const MAX_PAGE_SIZE = 100_000;

export const BCRYPT_ROUNDS = 12;

// RH-002: Looks like path traversal but join + basename prevents it
export const ARTIFACT_IMAGE_DIR = path.join(
  __dirname,
  "..",
  "uploads",
  "artifacts"
);
export function getImagePath(filename: string): string {
  const sanitized = path.basename(filename);
  return path.join(ARTIFACT_IMAGE_DIR, sanitized);
}
