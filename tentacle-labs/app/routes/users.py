"""User management endpoints for Tentacle Labs LIMS."""

import logging

from flask import Blueprint, request, jsonify, g

from app import db
from app.models import User, AuditLog
from app.auth import require_auth, require_role

users_bp = Blueprint("users", __name__)
logger = logging.getLogger(__name__)


@users_bp.route("/", methods=["GET"])
@require_auth
@require_role("admin")
def list_users():
    """List all users (admin only)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    department = request.args.get("department")

    query = User.query
    if department:
        query = query.filter_by(department=department)

    users = query.paginate(page=page, per_page=per_page, error_out=False)

    # BUG-056: User listing returns full user objects including API keys and password hashes (CWE-200, CVSS 6.5, HIGH, Tier 2)
    return jsonify({
        "users": [u.to_dict() for u in users.items],
        "total": users.total,
        "page": page,
    })


@users_bp.route("/<int:user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    """Get user profile."""
    user = User.query.get_or_404(user_id)

    # BUG-057: Any authenticated user can view any other user's full profile (CWE-639, CVSS 4.3, MEDIUM, Tier 1)
    return jsonify(user.to_dict())


@users_bp.route("/me", methods=["GET"])
@require_auth
def get_current_user():
    """Get current authenticated user profile."""
    return jsonify(g.current_user.to_dict())


@users_bp.route("/me", methods=["PUT"])
@require_auth
def update_profile():
    """Update current user's profile."""
    data = request.get_json()
    user = g.current_user

    if "username" in data:
        existing = User.query.filter_by(username=data["username"]).first()
        if existing and existing.id != user.id:
            return jsonify({"error": "Username already taken"}), 409
        user.username = data["username"]

    if "email" in data:
        user.email = data["email"]

    if "department" in data:
        user.department = data["department"]

    # BUG-058: Users can escalate their own role via profile update (CWE-269, CVSS 8.1, HIGH, Tier 1)
    if "role" in data:
        user.role = data["role"]

    if "password" in data:
        user.set_password(data["password"])

    db.session.commit()
    return jsonify(user.to_dict())


@users_bp.route("/<int:user_id>", methods=["PUT"])
@require_auth
@require_role("admin")
def admin_update_user(user_id):
    """Admin update of user profile."""
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if "username" in data:
        user.username = data["username"]
    if "email" in data:
        user.email = data["email"]
    if "role" in data:
        user.role = data["role"]
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "department" in data:
        user.department = data["department"]

    db.session.commit()

    audit = AuditLog(
        user_id=g.current_user.id,
        action="admin_update_user",
        resource_type="user",
        resource_id=user.id,
        details=f"Updated fields: {list(data.keys())}",
        ip_address=request.remote_addr,
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify(user.to_dict())


@users_bp.route("/<int:user_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_user(user_id):
    """Delete a user account."""
    user = User.query.get_or_404(user_id)

    # BUG-059: Admin can delete their own account, locking themselves out (CWE-754, CVSS N/A, BEST_PRACTICE, Tier 2)
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": f"User {user.username} deleted"})


@users_bp.route("/search", methods=["GET"])
@require_auth
def search_users():
    """Search users by username or email."""
    query_param = request.args.get("q", "")

    if not query_param:
        return jsonify({"error": "Search query required"}), 400

    # BUG-060: SQL injection in user search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    sql = f"SELECT * FROM users WHERE username LIKE '%{query_param}%' OR email LIKE '%{query_param}%'"
    result = db.session.execute(db.text(sql))
    rows = result.fetchall()

    users = []
    for row in rows:
        user = User.query.get(row[0])
        if user:
            users.append(user.to_dict())

    return jsonify({"users": users})


@users_bp.route("/bulk-create", methods=["POST"])
@require_auth
@require_role("admin")
def bulk_create_users():
    """Create multiple user accounts at once."""
    data = request.get_json()
    users_data = data.get("users", [])

    if not users_data:
        return jsonify({"error": "No users provided"}), 400

    created = []
    errors = []

    for user_data in users_data:
        try:
            username = user_data.get("username", "")
            email = user_data.get("email", "")
            password = user_data.get("password", "changeme")

            if User.query.filter_by(username=username).first():
                errors.append({"username": username, "error": "Already exists"})
                continue

            user = User(
                username=username,
                email=email,
                role=user_data.get("role", "researcher"),
                department=user_data.get("department", ""),
            )
            user.set_password(password)
            db.session.add(user)
            created.append(username)
        # BUG-061: Bare except hides real errors (CWE-754, CVSS N/A, BEST_PRACTICE, Tier 1)
        except:
            errors.append({"username": user_data.get("username", "?"), "error": "Creation failed"})

    db.session.commit()
    return jsonify({"created": created, "errors": errors})


@users_bp.route("/<int:user_id>/activity", methods=["GET"])
@require_auth
def user_activity(user_id):
    """Get user activity log."""
    # BUG-062: IDOR — any user can see any other user's activity (CWE-639, CVSS 4.3, MEDIUM, Tier 1)
    logs = AuditLog.query.filter_by(user_id=user_id).order_by(
        AuditLog.timestamp.desc()
    ).limit(100).all()

    return jsonify({
        "user_id": user_id,
        "activity": [
            {
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat(),
            }
            for log in logs
        ],
    })


@users_bp.route("/me/sessions", methods=["DELETE"])
@require_auth
def revoke_sessions():
    """Revoke all user sessions — placeholder (no actual session store)."""
    # BUG-063: Session revocation is a no-op — JWTs remain valid (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
    return jsonify({"message": "All sessions revoked"})
