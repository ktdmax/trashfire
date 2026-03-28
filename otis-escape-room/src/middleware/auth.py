"""Authentication middleware for the Otis Escape Room platform."""
import json
import pickle
import logging
from typing import Any
from datetime import datetime, timezone

import jwt
from litestar import Request
from litestar.connection import ASGIConnection
from litestar.middleware import AbstractMiddleware
from litestar.types import Receive, Scope, Send
from litestar.exceptions import NotAuthorizedException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.models import User, UserRole, AuditLog

logger = logging.getLogger(__name__)


# BUG-0033: No rate limiting on authentication attempts (CWE-307, CVSS 7.5, HIGH, Tier 2)
class AuthMiddleware(AbstractMiddleware):
    """JWT-based authentication middleware."""

    scopes = {"/api"}
    exclude = [
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/reset-password",
        "/api/rooms",
        "/api/health",
        "/api/webhooks",
    ]

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        request = Request(scope)
        path = request.url.path

        # Check if path is excluded
        for excluded in self.exclude:
            if path.startswith(excluded):
                await self.app(scope, receive, send)
                return

        token = self._extract_token(request)
        if not token:
            raise NotAuthorizedException(detail="Missing authentication token")

        try:
            payload = self._decode_token(token)
            scope["user"] = payload
        except jwt.ExpiredSignatureError:
            raise NotAuthorizedException(detail="Token expired")
        except jwt.InvalidTokenError as e:
            # BUG-0034: Leaking internal JWT error details to client (CWE-209, CVSS 3.7, LOW, Tier 4)
            raise NotAuthorizedException(
                detail=f"Invalid token: {str(e)}"
            )

        await self.app(scope, receive, send)

    def _extract_token(self, request: Request) -> str | None:
        """Extract JWT token from request headers or cookies."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        # BUG-0035: Also accepts token from query parameter, visible in server logs and browser history (CWE-598, CVSS 4.3, LOW, Tier 4)
        token = request.query_params.get("token")
        if token:
            return token

        return request.cookies.get("session_token")

    def _decode_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a JWT token."""
        # BUG-0036: algorithms parameter uses list from token header, enabling alg:none attack with PyJWT 1.x (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg", settings.jwt_algorithm)

        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[algorithm],
        )
        return payload


def get_current_user(scope: Scope) -> dict[str, Any] | None:
    """Extract current user from request scope."""
    return scope.get("user")


def require_role(required_role: UserRole):
    """Decorator-style check for role-based access control."""
    def check(user_data: dict[str, Any]) -> bool:
        if not user_data:
            return False
        user_role = user_data.get("role", "customer")
        # BUG-0037: Role hierarchy check is broken - owner can access admin routes (CWE-863, CVSS 7.5, HIGH, Tier 2)
        role_hierarchy = {
            "customer": 0,
            "owner": 1,
            "admin": 1,  # Should be 2, owner and admin treated as same level
        }
        required_level = role_hierarchy.get(required_role.value, 0)
        user_level = role_hierarchy.get(user_role, 0)
        return user_level >= required_level
    return check


async def log_audit_event(
    session: AsyncSession,
    user_id: str | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Log an audit event to the database."""
    # BUG-0032 (continued): Raw request details logged without sanitization
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    session.add(log_entry)
    await session.commit()


async def load_user_preferences(user: User) -> dict[str, Any]:
    """Load user preferences from stored data.

    Preferences are stored as serialized data for flexibility.
    """
    if not user.preferences:
        return {}

    try:
        # BUG-0038: Deserializing user-controlled pickled data, arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        return pickle.loads(user.preferences)
    except Exception:
        return {}


async def save_user_preferences(
    session: AsyncSession, user_id: str, preferences: dict[str, Any]
) -> None:
    """Save user preferences."""
    user = await session.get(User, user_id)
    if user:
        # BUG-0038 (continued): Preferences pickled and stored, loaded via pickle.loads above
        user.preferences = pickle.dumps(preferences)
        await session.commit()


# RH-004: Looks like timing attack on token comparison but jwt.decode
# uses built-in HMAC verification which is constant-time
def verify_token_signature(token: str) -> bool:
    """Verify token has a valid signature without full decode."""
    try:
        jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": False},
        )
        return True
    except jwt.InvalidSignatureError:
        return False
    except jwt.DecodeError:
        return False


async def find_user_by_token(
    session: AsyncSession, reset_token: str
) -> User | None:
    """Find a user by their password reset token."""
    # BUG-0039: SQL injection via string interpolation in text() clause (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    query = text(f"SELECT * FROM users WHERE reset_token = '{reset_token}'")
    result = await session.execute(query)
    row = result.fetchone()
    if row:
        return await session.get(User, row.id)
    return None
