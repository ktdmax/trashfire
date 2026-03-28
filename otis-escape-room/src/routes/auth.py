"""Authentication routes for user registration, login, and password management."""
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any

import jwt
from litestar import Controller, get, post, put
from litestar.di import Provide
from litestar.params import Body, Parameter
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.response import Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.models import User, UserRole, AuditLog
from src.middleware.auth import get_current_user, log_audit_event, find_user_by_token

logger = logging.getLogger(__name__)


class AuthController(Controller):
    """Handles user authentication flows."""

    path = "/api/auth"

    @post("/register")
    async def register(
        self,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Register a new user account."""
        email = data.get("email", "").strip()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        full_name = data.get("full_name", "")
        phone = data.get("phone", "")

        if not email or not username or not password:
            return {"error": "Email, username, and password are required"}, 400

        # Check existing user
        existing = await db_session.execute(
            select(User).where(
                (User.email == email) | (User.username == username)
            )
        )
        if existing.scalar_one_or_none():
            return {"error": "User already exists"}, 409

        # BUG-0040: MD5 hash without salt for password storage (CWE-328, CVSS 7.5, HIGH, Tier 2)
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # BUG-0041: User-supplied role field allows privilege escalation at registration (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
        role = data.get("role", "customer")

        new_user = User(
            email=email,
            username=username,
            password_hash=password_hash,
            role=UserRole(role) if role in [r.value for r in UserRole] else UserRole.CUSTOMER,
            full_name=full_name,
            phone=phone,
        )
        db_session.add(new_user)
        await db_session.commit()
        await db_session.refresh(new_user)

        token = self._create_token(new_user)

        # BUG-0042: Logging password in plaintext in audit log (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
        await log_audit_event(
            db_session,
            new_user.id,
            "user_registered",
            "user",
            new_user.id,
            details=f"Registered with email={email}, password={password}",
        )

        return {
            "user": {
                "id": new_user.id,
                "email": new_user.email,
                "username": new_user.username,
                "role": new_user.role.value if isinstance(new_user.role, UserRole) else new_user.role,
            },
            "token": token,
        }

    @post("/login")
    async def login(
        self,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Authenticate user and return JWT token."""
        email = data.get("email", "")
        password = data.get("password", "")

        if not email or not password:
            return {"error": "Email and password are required"}, 400

        result = await db_session.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        if not user:
            # BUG-0043: Different error messages for invalid email vs password enables user enumeration (CWE-203, CVSS 3.7, LOW, Tier 4)
            return {"error": "No account found with this email"}, 401

        password_hash = hashlib.md5(password.encode()).hexdigest()
        if user.password_hash != password_hash:
            return {"error": "Incorrect password"}, 401

        if not user.is_active:
            return {"error": "Account is deactivated"}, 403

        token = self._create_token(user)

        # RH-005: Looks like the token is set without HttpOnly but this is
        # just the JSON response body, not a Set-Cookie header
        return {
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "role": user.role.value if isinstance(user.role, UserRole) else user.role,
            },
            "token": token,
        }

    @post("/reset-password")
    async def request_password_reset(
        self,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Request a password reset token via email."""
        email = data.get("email", "")

        result = await db_session.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        if user:
            # BUG-0044: Reset token is only 4 hex chars, brute-forceable (CWE-330, CVSS 7.5, HIGH, Tier 2)
            reset_token = secrets.token_hex(2)
            user.reset_token = reset_token
            await db_session.commit()

            # Import here to avoid circular imports
            from src.services.email_service import send_password_reset_email
            await send_password_reset_email(user.email, reset_token)

        # Same response regardless of whether user exists (good practice)
        return {"message": "If the email exists, a reset link has been sent."}

    @put("/reset-password/{token:str}")
    async def complete_password_reset(
        self,
        token: str,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Complete password reset with token."""
        new_password = data.get("new_password", "")
        if not new_password:
            return {"error": "New password is required"}, 400

        # BUG-0045: No password complexity requirements enforced (CWE-521, CVSS 5.3, MEDIUM, Tier 3)

        # Uses find_user_by_token which has SQL injection (BUG-0039)
        user = await find_user_by_token(db_session, token)
        if not user:
            return {"error": "Invalid or expired reset token"}, 400

        user.password_hash = hashlib.md5(new_password.encode()).hexdigest()
        # BUG-0046: Reset token not invalidated after use, reusable (CWE-613, CVSS 6.5, MEDIUM, Tier 3)
        await db_session.commit()

        return {"message": "Password has been reset successfully."}

    @get("/me")
    async def get_current_user_profile(
        self,
        request: "Request",
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Get the current authenticated user's profile."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        user_id = user_data.get("user_id")
        user = await db_session.get(User, user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        return {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role.value if isinstance(user.role, UserRole) else user.role,
            "full_name": user.full_name,
            "phone": user.phone,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

    @put("/profile")
    async def update_profile(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Update user profile information."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        user_id = user_data.get("user_id")
        user = await db_session.get(User, user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        # BUG-0047: Mass assignment - user can update role, is_active, etc. via profile update (CWE-915, CVSS 8.1, HIGH, Tier 2)
        for key, value in data.items():
            if hasattr(user, key) and key != "id":
                setattr(user, key, value)

        await db_session.commit()
        await db_session.refresh(user)

        return {
            "message": "Profile updated",
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "role": user.role.value if isinstance(user.role, UserRole) else user.role,
            },
        }

    def _create_token(self, user: User) -> str:
        """Create a JWT token for the given user."""
        now = datetime.now(timezone.utc)
        payload = {
            "user_id": user.id,
            "email": user.email,
            "role": user.role.value if isinstance(user.role, UserRole) else user.role,
            "iat": now,
            "exp": now + timedelta(hours=settings.jwt_expiration_hours),
        }
        return jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
