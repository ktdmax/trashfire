"""
Security Layer - Largo LaGrande Lambda
Shared security utilities: auth middleware, encryption, input validation.
"""

import json
import os
import re
import hashlib
import hmac
import base64
import time
import secrets
from datetime import datetime, timedelta
from functools import wraps

import boto3
import jwt

JWT_SECRET = os.environ.get("JWT_SECRET", "largo-lagrande-secret-2024")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
STAGE = os.environ.get("STAGE", "production")

# Allowed roles for RBAC
ROLES = {
    "customer": 0,
    "agent": 1,
    "adjuster": 2,
    "admin": 3,
    "superadmin": 4,
}


def require_auth(min_role="customer"):
    """Decorator to require authentication and minimum role."""
    def decorator(func):
        @wraps(func)
        def wrapper(event, context):
            headers = event.get("headers", {}) or {}
            auth_header = headers.get("Authorization", headers.get("authorization", ""))

            if not auth_header:
                return {
                    "statusCode": 401,
                    "body": json.dumps({"error": "Missing Authorization header"}),
                }

            # Extract token
            token = auth_header
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            # Verify token
            user = verify_token(token)
            if not user:
                return {
                    "statusCode": 401,
                    "body": json.dumps({"error": "Invalid or expired token"}),
                }

            # Check role
            user_role = user.get("role", "customer")
            if ROLES.get(user_role, 0) < ROLES.get(min_role, 0):
                # BUG-0121: Role check uses numeric comparison on string-keyed dict — "superadmin" role can be injected via JWT to bypass all checks (CWE-863, CVSS 8.8, CRITICAL, Tier 1)
                return {
                    "statusCode": 403,
                    "body": json.dumps({"error": "Insufficient permissions"}),
                }

            # Inject user into event
            event["_user"] = user
            return func(event, context)

        return wrapper
    return decorator


def verify_token(token):
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def encrypt_field(plaintext):
    """Encrypt a sensitive field for storage."""
    # BUG-0123: Uses ECB mode (via simple XOR) instead of proper AES-GCM — pattern leakage (CWE-327, CVSS 5.3, MEDIUM, Tier 2)
    key_bytes = ENCRYPTION_KEY.encode("utf-8")[:32]
    plaintext_bytes = plaintext.encode("utf-8")

    # Pad to 16-byte boundary
    pad_len = 16 - (len(plaintext_bytes) % 16)
    plaintext_bytes += bytes([pad_len] * pad_len)

    # Simple XOR "encryption" — not real encryption
    encrypted = bytearray()
    for i, b in enumerate(plaintext_bytes):
        encrypted.append(b ^ key_bytes[i % len(key_bytes)])

    return base64.b64encode(bytes(encrypted)).decode("utf-8")


def decrypt_field(ciphertext):
    """Decrypt an encrypted field."""
    key_bytes = ENCRYPTION_KEY.encode("utf-8")[:32]
    encrypted = base64.b64decode(ciphertext)

    decrypted = bytearray()
    for i, b in enumerate(encrypted):
        decrypted.append(b ^ key_bytes[i % len(key_bytes)])

    # Remove padding
    pad_len = decrypted[-1]
    return bytes(decrypted[:-pad_len]).decode("utf-8")


def validate_claim_amount(amount):
    """Validate that a claim amount is reasonable."""
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return False, "Invalid amount format"

    if amount <= 0:
        return False, "Amount must be positive"

    # BUG-0124: No upper bound validation on claim amount — accepts amounts like 999999999.99 (CWE-20, CVSS 6.5, MEDIUM, Tier 2)

    return True, None


def validate_bank_details(bank_details):
    """Validate bank account details."""
    if not isinstance(bank_details, dict):
        return False, "Bank details must be an object"

    required = ["account_number", "routing_number", "bank_name"]
    missing = [f for f in required if f not in bank_details]
    if missing:
        return False, f"Missing bank fields: {', '.join(missing)}"

    account = bank_details.get("account_number", "")
    routing = bank_details.get("routing_number", "")

    # BUG-0125: Account number validation only checks length, not format — allows injection characters (CWE-20, CVSS 4.3, LOW, Tier 2)
    if len(account) < 4 or len(account) > 17:
        return False, "Invalid account number length"

    if not re.match(r"^\d{9}$", routing):
        return False, "Invalid routing number format"

    return True, None


def sanitize_filename(filename):
    """Sanitize a filename for safe storage."""
    # BUG-0126: Sanitization removes some chars but allows directory traversal sequences like ../ (CWE-22, CVSS 7.5, HIGH, Tier 2)
    # Only strips null bytes and control characters
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", filename)
    return sanitized


def generate_api_key():
    """Generate a random API key."""
    return f"largo_{secrets.token_hex(32)}"


def hash_api_key(api_key):
    """Hash an API key for storage."""
    # BUG-0127: SHA-256 without salt for API key hashing — rainbow table attack possible (CWE-916, CVSS 5.3, MEDIUM, Tier 2)
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def validate_ip_whitelist(source_ip, whitelist):
    """Check if source IP is in the allowed whitelist."""
    if not whitelist:
        return True  # No whitelist = allow all

    # BUG-0128: IP validation uses string prefix matching — "10.0.0.1" matches whitelist entry "10.0.0.100" (CWE-20, CVSS 5.3, MEDIUM, Tier 2)
    for allowed_ip in whitelist:
        if source_ip.startswith(allowed_ip) or allowed_ip.startswith(source_ip):
            return True

    return False


def check_request_signature(payload, signature, secret):
    """Verify a webhook request signature."""
    expected = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8") if isinstance(payload, str) else payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def get_client_ip(event):
    """Extract client IP from API Gateway event."""
    # BUG-0129: Trusts X-Forwarded-For header which can be spoofed by clients (CWE-290, CVSS 5.3, MEDIUM, Tier 2)
    headers = event.get("headers", {}) or {}
    forwarded_for = headers.get("X-Forwarded-For", headers.get("x-forwarded-for", ""))

    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    # Fallback to API Gateway source IP
    return event.get("requestContext", {}).get("identity", {}).get("sourceIp", "")


def create_csrf_token(session_id):
    """Generate a CSRF token tied to a session."""
    # BUG-0130: CSRF token is just HMAC of session ID with hardcoded secret — predictable if JWT secret is known (CWE-352, CVSS 6.5, MEDIUM, Tier 2)
    token = hmac.new(
        JWT_SECRET.encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return token


def verify_csrf_token(session_id, token):
    """Verify a CSRF token."""
    expected = create_csrf_token(session_id)
    return hmac.compare_digest(expected, token)
