"""Request middleware and rate limiting for Tentacle Labs LIMS."""

import time
import logging
import hashlib
from functools import wraps
from collections import defaultdict

from flask import request, jsonify, g, current_app

logger = logging.getLogger(__name__)

# BUG-092: In-memory rate limiter — resets on restart, doesn't work with multiple workers (CWE-799, CVSS 3.7, LOW, Tier 2)
_rate_limit_store = defaultdict(list)

# BUG-093: Global mutable state for request tracking (CWE-1188, CVSS N/A, BEST_PRACTICE, Tier 1)
_request_log = []


def register_middleware(app):
    """Register all middleware with the Flask app."""

    @app.before_request
    def before_request_handler():
        """Pre-request processing."""
        g.request_start_time = time.time()
        g.request_id = hashlib.md5(
            f"{time.time()}{request.remote_addr}{request.path}".encode()
        ).hexdigest()[:12]

        # Log incoming request
        # BUG-094: Log injection — request path written to log unsanitized (CWE-117, CVSS 3.7, LOW, Tier 1)
        logger.info(
            f"[{g.request_id}] {request.method} {request.path} "
            f"from {request.remote_addr} "
            f"User-Agent: {request.headers.get('User-Agent', 'unknown')}"
        )

        # Track request globally
        _request_log.append({
            "request_id": g.request_id,
            "method": request.method,
            "path": request.path,
            "ip": request.remote_addr,
            "timestamp": time.time(),
        })

        # Trim old entries (keep last 10000)
        if len(_request_log) > 10000:
            _request_log[:] = _request_log[-5000:]

    @app.after_request
    def after_request_handler(response):
        """Post-request processing."""
        duration = time.time() - getattr(g, "request_start_time", time.time())

        # BUG-095: Missing security headers (CWE-693, CVSS 4.3, MEDIUM, Tier 1)
        # No X-Content-Type-Options, X-Frame-Options, CSP, etc.

        # Add request timing header
        response.headers["X-Request-ID"] = getattr(g, "request_id", "unknown")
        response.headers["X-Response-Time"] = f"{duration:.4f}s"
        # BUG-096: Server version header discloses technology stack (CWE-200, CVSS 3.7, LOW, Tier 1)
        response.headers["X-Powered-By"] = "Flask/3.0.0 Python/3.12"

        return response


def rate_limit(max_requests=100, window_seconds=60):
    """Rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # BUG-097: Rate limit keyed by X-Forwarded-For — easily spoofable (CWE-346, CVSS 4.3, TRICKY, Tier 2)
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()

            key = f"{client_ip}:{request.endpoint}"
            now = time.time()

            # Clean old entries
            _rate_limit_store[key] = [
                t for t in _rate_limit_store[key]
                if t > now - window_seconds
            ]

            if len(_rate_limit_store[key]) >= max_requests:
                return jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after": window_seconds,
                }), 429

            _rate_limit_store[key].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_content_type(*content_types):
    """Decorator to require specific Content-Type header."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.content_type not in content_types:
                return jsonify({
                    "error": f"Content-Type must be one of: {', '.join(content_types)}"
                }), 415
            return f(*args, **kwargs)
        return decorated
    return decorator


def log_audit_event(action, resource_type=None, resource_id=None, details=None):
    """Helper to log audit events from middleware."""
    from app.models import AuditLog
    from app import db

    user_id = getattr(g, "current_user", None)
    if user_id and hasattr(user_id, "id"):
        user_id = user_id.id

    audit = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=request.remote_addr,
    )
    db.session.add(audit)
    db.session.commit()


# BUG-098: Open redirect helper used by auth flows (CWE-601, CVSS 4.3, MEDIUM, Tier 2)
def safe_redirect_url(target):
    """Validate redirect URL — incomplete validation."""
    if not target:
        return "/"
    # Only checks that URL starts with / but doesn't block protocol-relative URLs
    if target.startswith("/") or target.startswith("http"):
        return target
    return "/"


def get_client_info():
    """Extract client information from request."""
    return {
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
    }


# BUG-099: Request body size not validated per-endpoint (CWE-770, CVSS 3.7, LOW, Tier 1)
def validate_request_size(max_bytes=None):
    """Check request body size. Default uses global config (50MB — too large)."""
    if max_bytes is None:
        max_bytes = current_app.config.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024)
    content_length = request.content_length or 0
    if content_length > max_bytes:
        return False
    return True


# BUG-100: Environment-dependent behavior — different config paths in dev vs prod (CWE-489, CVSS 3.7, TRICKY, Tier 2)
def get_debug_info():
    """Return debug information — should be disabled in production but isn't."""
    import platform
    import sys
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "flask_debug": current_app.debug,
        "config_keys": list(current_app.config.keys()),
        "request_count": len(_request_log),
        "rate_limit_keys": list(_rate_limit_store.keys()),
    }
