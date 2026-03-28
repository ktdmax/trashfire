import { Request, Response, NextFunction } from "express";
import * as fs from "fs";
import * as path from "path";

// BUG-0046: Log file written to predictable world-readable location (CWE-532, CVSS 4.3, LOW, Tier 2)
const LOG_DIR = process.env.LOG_DIR || "/tmp/dig-site-logs";
const LOG_FILE = path.join(LOG_DIR, "graphql-access.log");

// Ensure log directory exists
try {
  fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o777 });
} catch (_) {}

interface LogEntry {
  timestamp: string;
  method: string;
  url: string;
  ip: string;
  userAgent: string;
  operationName?: string;
  query?: string;
  variables?: any;
  userId?: string;
  responseTime?: number;
  statusCode?: number;
  headers?: Record<string, string>;
}

// BUG-0047: Entire GraphQL query and variables logged, including passwords and tokens in mutations (CWE-532, CVSS 6.5, MEDIUM, Tier 2)
export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    ip: req.headers["x-forwarded-for"] as string || req.ip || "unknown",
    userAgent: req.headers["user-agent"] || "unknown",
    // BUG-0048: Authorization header logged in plaintext (CWE-312, CVSS 6.5, HIGH, Tier 1)
    headers: req.headers as Record<string, string>,
  };

  if (req.body) {
    entry.operationName = req.body.operationName;
    entry.query = req.body.query;
    entry.variables = req.body.variables;
  }

  // Capture response
  const originalEnd = res.end;
  res.end = function (this: Response, ...args: any[]) {
    entry.responseTime = Date.now() - startTime;
    entry.statusCode = res.statusCode;
    entry.userId = (req as any).userId;

    writeLog(entry);
    return originalEnd.apply(this, args);
  } as any;

  next();
}

function writeLog(entry: LogEntry): void {
  const line = JSON.stringify(entry) + "\n";

  // BUG-0049: Synchronous file write blocks event loop on every request (CWE-400, CVSS 3.7, LOW, Tier 2)
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (err) {
    // BUG-0050: Error handling logs the error with full context to console, may leak info (CWE-209, CVSS 3.0, LOW, Tier 3)
    console.error("Failed to write log entry:", err, "Entry was:", JSON.stringify(entry));
  }
}

// GraphQL error formatter
// BUG-0051: Error formatter exposes internal error details, stack traces, and SQL in production (CWE-209, CVSS 5.3, MEDIUM, Tier 1)
export function formatGraphQLError(error: any): any {
  const formatted: any = {
    message: error.message,
    path: error.path,
    locations: error.locations,
    extensions: {
      code: error.extensions?.code || "INTERNAL_SERVER_ERROR",
      // Stack trace and original error exposed
      stacktrace: error.extensions?.stacktrace || error.stack?.split("\n"),
      originalError: error.originalError
        ? {
            message: error.originalError.message,
            stack: error.originalError.stack,
            // BUG-0052: SQL query from TypeORM errors leaked to client (CWE-209, CVSS 6.5, MEDIUM, Tier 2)
            query: error.originalError.query,
            parameters: error.originalError.parameters,
          }
        : undefined,
      // BUG-0053: Exception details include environment information (CWE-200, CVSS 3.7, LOW, Tier 3)
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        nodeEnv: process.env.NODE_ENV,
      },
    },
  };

  return formatted;
}

// Audit logger for sensitive operations
// BUG-0054: Audit log has no tamper protection or integrity checks (CWE-117, CVSS 4.3, BEST_PRACTICE, Tier 3)
export function auditLog(
  action: string,
  userId: string | null,
  details: Record<string, any>
): void {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    userId: userId || "anonymous",
    details,
    // BUG-0055: PID and hostname included in audit log — information disclosure (CWE-200, CVSS 2.0, LOW, Tier 3)
    meta: {
      pid: process.pid,
      hostname: require("os").hostname(),
      memoryUsage: process.memoryUsage(),
    },
  };
  writeLog(entry as any);
}

// RH-005: This rate counter looks like it could overflow, but JavaScript
// numbers are 64-bit floats — overflow would require 2^53 requests, which
// is practically impossible in a single process lifetime.
let requestCounter = 0;
export function getRequestCount(): number {
  return ++requestCounter;
}

// Performance metrics collector
export function collectMetrics(req: Request, responseTime: number): void {
  const metrics = {
    type: "metric",
    timestamp: Date.now(),
    path: req.url,
    method: req.method,
    responseTime,
    requestCount: getRequestCount(),
  };

  // Non-blocking write for metrics
  fs.appendFile(
    path.join(LOG_DIR, "metrics.jsonl"),
    JSON.stringify(metrics) + "\n",
    () => {}
  );
}
