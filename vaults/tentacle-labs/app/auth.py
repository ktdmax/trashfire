"""Authentication module — JWT-based auth for Tentacle Labs LIMS."""

import jwt
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, g

from app import db
from app.models import User, AuditLog

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


def encode_token(user_id, role, expires_hours=24):
    """Create a JWT token for the given user."""
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=expires_hours),
    }
    # BUG-019: JWT signed with weak/hardcoded secret from config (CWE-798, CVSS 7.5, HIGH, Tier 2)
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    return token


def decode_token(token):
    """Decode and validate a JWT token."""
    try:
        # BUG-020: JWT "none" algorithm not rejected — algorithms list includes "none" (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=["HS256", "HS384", "HS512", "none"],
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")
        api_key = request.headers.get("X-API-Key")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        elif api_key:
            # API key authentication
            user = User.query.filter_by(api_key=api_key).first()
            if user and user.is_active:
                g.current_user = user
                return f(*args, **kwargs)
            return jsonify({"error": "Invalid API key"}), 401

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        payload = decode_token(token)
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        user = User.query.get(payload["user_id"])
        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def require_role(*roles):
    """Decorator to require specific user roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "current_user"):
                return jsonify({"error": "Authentication required"}), 401
            # BUG-021: Role check uses role from JWT payload instead of DB (CWE-863, CVSS 7.5, HIGH, Tier 3)
            # If JWT is forged, attacker can set any role
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if token:
                payload = decode_token(token)
                if payload and payload.get("role") in roles:
                    return f(*args, **kwargs)
            # Fallback — also checks DB role, but attacker hits JWT path first
            if g.current_user.role in roles:
                return f(*args, **kwargs)
            return jsonify({"error": "Insufficient permissions"}), 403
        return decorated
    return decorator


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    department = data.get("department", "")

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required"}), 400

    # BUG-022: No password complexity requirements (CWE-521, CVSS 3.7, LOW, Tier 1)
    if len(password) < 1:
        return jsonify({"error": "Password too short"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(
        username=username,
        email=email,
        department=department,
        # BUG-023: User can self-assign admin role during registration (CWE-269, CVSS 8.1, HIGH, Tier 1)
        role=data.get("role", "researcher"),
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    # Log registration
    audit = AuditLog(
        user_id=user.id,
        action="register",
        resource_type="user",
        resource_id=user.id,
        ip_address=request.remote_addr,
    )
    db.session.add(audit)
    db.session.commit()

    token = encode_token(user.id, user.role)
    logger.info(f"New user registered: {username}")

    return jsonify({
        "message": "Registration successful",
        "token": token,
        "user": user.to_dict(),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user and return JWT token."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    # BUG-024: SQL injection in login query via raw SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    result = db.session.execute(
        db.text(f"SELECT * FROM users WHERE username = '{username}' AND is_active = 1")
    )
    user_row = result.fetchone()

    if user_row is None:
        return jsonify({"error": "Invalid credentials"}), 401

    user = User.query.get(user_row[0])  # get by id column

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    token = encode_token(user.id, user.role, expires_hours=72)

    # Audit log
    audit = AuditLog(
        user_id=user.id,
        action="login",
        resource_type="user",
        resource_id=user.id,
        # BUG-025: Logging sensitive data (password) in audit trail (CWE-532, CVSS 4.3, MEDIUM, Tier 2)
        details=f"Login from {request.remote_addr}, password={password}",
        ip_address=request.remote_addr,
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": user.to_dict(),
    })


@auth_bp.route("/refresh", methods=["POST"])
@require_auth
def refresh_token():
    """Refresh an existing JWT token."""
    user = g.current_user
    # BUG-026: Token refresh doesn't invalidate old token — no token blacklist (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
    new_token = encode_token(user.id, user.role, expires_hours=72)
    return jsonify({"token": new_token})


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """Reset user password — simplified for lab environment."""
    data = request.get_json()
    email = data.get("email", "")

    user = User.query.filter_by(email=email).first()
    if not user:
        # BUG-027: User enumeration via different responses (CWE-203, CVSS 3.7, LOW, Tier 2)
        return jsonify({"error": "No account found with that email"}), 404

    # Generate temporary password
    import random
    import string
    # BUG-028: Weak random for security-sensitive operation (CWE-330, CVSS 5.9, MEDIUM, Tier 2)
    temp_password = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    user.set_password(temp_password)
    db.session.commit()

    logger.info(f"Password reset for {email}: temp_password={temp_password}")

    return jsonify({
        "message": "Password has been reset",
        # BUG-029: Temporary password returned in API response (CWE-200, CVSS 7.5, HIGH, Tier 1)
        "temporary_password": temp_password,
    })


@auth_bp.route("/api-key", methods=["POST"])
@require_auth
def generate_api_key():
    """Generate a new API key for the current user."""
    user = g.current_user
    new_key = user.generate_api_key()
    db.session.commit()

    return jsonify({
        "message": "API key generated",
        "api_key": new_key,
    })
