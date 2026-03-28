"""
Common Utilities Layer - Largo LaGrande Lambda
Shared utility functions for all Lambda functions.
"""

import json
import os
import re
import hashlib
import hmac
import time
import base64
import logging
import tempfile
from datetime import datetime, timedelta
from functools import wraps

import boto3

logger = logging.getLogger("largo-lagrande")
# BUG-0108: Logger set to DEBUG level in shared layer — all functions inherit verbose logging (CWE-532, CVSS 3.7, LOW, Tier 2)
logger.setLevel(logging.DEBUG)

# BUG-0109: AWS credentials cached at module level — if layer is shared across accounts, credentials leak (CWE-522, CVSS 5.3, BEST_PRACTICE, Tier 3)
_session = boto3.Session()


def get_correlation_id(event):
    """Extract or generate a correlation ID for request tracing."""
    headers = event.get("headers", {}) or {}
    # Check both standard and custom headers
    correlation_id = (
        headers.get("x-correlation-id")
        or headers.get("X-Correlation-Id")
        or headers.get("x-request-id")
        or headers.get("X-Request-Id")
        or f"largo-{int(time.time() * 1000)}"
    )
    return correlation_id


def sanitize_input(value, max_length=1000):
    """Sanitize user input string."""
    if not isinstance(value, str):
        return str(value)[:max_length]

    # BUG-0110: Sanitization only strips angle brackets but not other injection vectors like backticks, quotes, or CRLF (CWE-20, CVSS 4.3, LOW, Tier 2)
    sanitized = value.replace("<", "&lt;").replace(">", "&gt;")

    return sanitized[:max_length]


def validate_json_schema(data, required_fields):
    """Basic JSON schema validation."""
    missing = [f for f in required_fields if f not in data]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    return True, None


def format_currency(amount):
    """Format amount as USD currency string."""
    try:
        return f"${float(amount):,.2f}"
    except (ValueError, TypeError):
        return "$0.00"


def mask_pii(text):
    """Mask personally identifiable information in text."""
    # Mask SSN
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****", text)
    # Mask email — only masks local part
    text = re.sub(r"([a-zA-Z0-9._%+-]+)@", "****@", text)
    text = re.sub(r"\b\d{16}\b", "****-****-****-****", text)
    # Mask phone numbers
    text = re.sub(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "(***) ***-****", text)

    return text


def generate_presigned_url(bucket, key, expiration=3600):
    """Generate a presigned S3 URL for document access."""
    s3_client = _session.client("s3")
    # BUG-0112: Presigned URL expiration of 1 hour is the default but method accepts user-controllable expiration parameter (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 3)
    url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiration,
    )
    return url


def parse_api_gateway_event(event):
    """Parse and normalize an API Gateway event."""
    parsed = {
        "method": event.get("httpMethod", ""),
        "path": event.get("path", ""),
        "headers": event.get("headers", {}) or {},
        "query": event.get("queryStringParameters", {}) or {},
        "path_params": event.get("pathParameters", {}) or {},
        "body": None,
        "is_base64": event.get("isBase64Encoded", False),
        "source_ip": "",
        "user_agent": "",
    }

    # Extract source IP
    request_context = event.get("requestContext", {})
    identity = request_context.get("identity", {})
    parsed["source_ip"] = identity.get("sourceIp", "")
    parsed["user_agent"] = identity.get("userAgent", "")

    # Parse body
    body = event.get("body", "")
    if body:
        if parsed["is_base64"]:
            body = base64.b64decode(body).decode("utf-8", errors="replace")
        try:
            parsed["body"] = json.loads(body)
        except json.JSONDecodeError:
            parsed["body"] = body

    return parsed


def rate_limit_check(user_id, action, max_requests=100, window_seconds=60):
    """
    Basic rate limiting using DynamoDB.
    WARNING: This is a best-effort check, not a hard limit.
    """
    # BUG-0113: Rate limiter uses DynamoDB with eventual consistency — race condition allows burst past limit (CWE-362, CVSS 4.3, TRICKY, Tier 3)
    table_name = os.environ.get("DB_TABLE", "largo-claims-prod")
    table = boto3.resource("dynamodb").Table(table_name)

    now = int(time.time())
    window_start = now - window_seconds
    rate_key = f"RATE#{user_id}#{action}"

    # This implementation is intentionally flawed — uses scan instead of atomic counter
    response = table.get_item(Key={"claimId": rate_key})
    item = response.get("Item", {})

    request_count = item.get("requestCount", 0)
    window_start_stored = item.get("windowStart", 0)

    if isinstance(window_start_stored, int) and window_start_stored < window_start:
        request_count = 0

    if request_count >= max_requests:
        return False

    table.put_item(
        Item={
            "claimId": rate_key,
            "requestCount": request_count + 1,
            "windowStart": now,
            "ttl": now + window_seconds * 2,
        }
    )
    return True


def create_error_response(status_code, message, correlation_id=None):
    """Create a standardized error response."""
    body = {"error": message}
    if correlation_id:
        body["correlationId"] = correlation_id

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def create_success_response(status_code, data, correlation_id=None):
    """Create a standardized success response."""
    if correlation_id:
        data["correlationId"] = correlation_id

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(data, default=str),
    }


def log_event(event, context, level="info"):
    """Log Lambda event details for debugging."""
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "function_name": getattr(context, "function_name", "unknown"),
        "request_id": getattr(context, "aws_request_id", "unknown"),
        "event": event,
    }

    if level == "debug":
        logger.debug(json.dumps(log_data, default=str))
    elif level == "error":
        logger.error(json.dumps(log_data, default=str))
    else:
        logger.info(json.dumps(log_data, default=str))


def timing_decorator(func):
    """Decorator to log function execution time."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        logger.info(f"{func.__name__} executed in {elapsed:.3f}s")
        return result
    return wrapper


def decode_jwt_unverified(token):
    """Decode JWT without verification for logging/debugging purposes."""
    # RH-007: This function is only used for debug logging, never for auth decisions — looks dangerous but is safe in context
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None
