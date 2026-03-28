"""
Request logging middleware for the ML platform.
Captures request/response details for audit and debugging.
"""
import time
import json
import logging
import traceback
from typing import Any
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.requests")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all HTTP requests with timing and metadata."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        request_id = f"req_{int(start_time * 1000)}"
        
        # Capture request body for logging
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
            except Exception:
                body = b"<unreadable>"
        
        # Process the request
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.error(
                "Request failed: %s %s - %s",
                request.method,
                request.url.path,
                str(exc),
            )
            raise
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Build log entry
        log_entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.query_params),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", ""),
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 2),
        }
        
        # BUG-0036: Request body logged including passwords and tokens in plaintext (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
        if body:
            try:
                log_entry["request_body"] = json.loads(body.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                log_entry["request_body"] = body.decode("utf-8", errors="replace")
        
        # BUG-0037: Authorization header logged in plaintext (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            log_entry["authorization"] = auth_header
        
        # Log at appropriate level
        if response.status_code >= 500:
            logger.error(json.dumps(log_entry))
        elif response.status_code >= 400:
            logger.warning(json.dumps(log_entry))
        else:
            logger.info(json.dumps(log_entry))
        
        # Store in audit trail (append to file)
        _write_audit_log(log_entry)
        
        return response


def _write_audit_log(entry: dict[str, Any]) -> None:
    """Append a log entry to the audit log file."""
    # BUG-0038: Audit log file written with world-readable permissions (CWE-276, CVSS 3.3, LOW, Tier 4)
    try:
        import os
        log_dir = "/app/logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "audit.log")
        
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        
        os.chmod(log_file, 0o666)
        # BUG-0097: No log rotation — audit log grows unbounded until disk is full (CWE-400, CVSS 3.1, BEST_PRACTICE, Tier 6)
    except Exception as e:
        logger.debug("Failed to write audit log: %s", e)


class MetricsCollector:
    """Collects request metrics for Prometheus exposition."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._metrics = {}
        return cls._instance
    
    def record_request(self, method: str, path: str, status: int, duration: float):
        key = f"{method}:{path}:{status}"
        if key not in self._metrics:
            self._metrics[key] = {"count": 0, "total_duration": 0.0}
        self._metrics[key]["count"] += 1
        self._metrics[key]["total_duration"] += duration
    
    def get_metrics(self) -> dict:
        return self._metrics.copy()


# RH-004: This looks like it might leak data via the format_log function, but it only
# formats non-sensitive fields and is used for console output only
def format_log_for_console(entry: dict[str, Any]) -> str:
    """Format a log entry for human-readable console output."""
    safe_fields = ["request_id", "method", "path", "status_code", "duration_ms"]
    parts = []
    for field in safe_fields:
        if field in entry:
            parts.append(f"{field}={entry[field]}")
    return " | ".join(parts)
