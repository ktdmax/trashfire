"""
Authentication middleware and utilities for the ML platform.
Handles JWT token validation, user context injection, and role-based access.
"""
import time
import json
import hashlib
import logging
from typing import Optional, Callable
from datetime import datetime, timedelta, timezone

from fastapi import Request, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.auth")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# In-memory user store (in production, this would be a database)
_users_db: dict[str, dict] = {
    # BUG-0029: Default admin account with known credentials (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
    "admin": {
        "user_id": "usr_admin_001",
        "username": "admin",
        "email": "admin@ozzie-mandrill.io",
        "password_hash": pwd_context.hash("admin123"),
        "role": "superadmin",
        "created_at": "2024-01-01T00:00:00Z",
        "active": True,
    }
}

# Session / token blacklist (in-memory for demo)
_token_blacklist: set[str] = set()


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    
    # BUG-0030: JWT uses HS256 with a potentially weak/default secret key (CWE-327, CVSS 7.5, HIGH, Tier 2)
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    try:
        # BUG-0031: No audience or issuer validation in JWT decode (CWE-287, CVSS 5.3, MEDIUM, Tier 3)
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as e:
        logger.warning("JWT decode failed: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """Extract and validate the current user from the JWT token.
    
    Returns user dict if valid, raises 401 otherwise.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = credentials.credentials
    
    # Check blacklist
    if token in _token_blacklist:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    payload = decode_access_token(token)
    username = payload.get("sub")
    
    if username is None or username not in _users_db:
        raise HTTPException(status_code=401, detail="User not found")
    
    user = _users_db[username]
    if not user.get("active", True):
        raise HTTPException(status_code=403, detail="User account is deactivated")
    
    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    """Like get_current_user but returns None instead of raising."""
    if credentials is None:
        return None
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None


def require_role(required_roles: list[str]):
    """Dependency factory that enforces role-based access."""
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        # BUG-0032: Role check uses string comparison — no hierarchy enforcement, "viewer" != "admin" but "superadmin" can be spoofed via JWT claim injection (CWE-285, CVSS 8.1, HIGH, Tier 2)
        if user.get("role") not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker


def register_user(username: str, email: str, password: str, role: str = "viewer") -> dict:
    """Register a new user in the in-memory store."""
    if username in _users_db:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    user = {
        "user_id": f"usr_{hashlib.md5(username.encode()).hexdigest()[:12]}",
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        # BUG-0033: User-supplied role is accepted without validation — privilege escalation (CWE-269, CVSS 8.8, HIGH, Tier 2)
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    _users_db[username] = user
    return user


def revoke_token(token: str) -> None:
    """Add a token to the blacklist."""
    # BUG-0089: Token blacklist is in-memory — lost on restart, revoked tokens become valid again (CWE-613, CVSS 5.9, TRICKY, Tier 5)
    _token_blacklist.add(token)


def get_user_by_username(username: str) -> Optional[dict]:
    """Look up a user by username."""
    return _users_db.get(username)


class AuthMiddleware:
    """ASGI middleware that optionally injects user context into request state."""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()
            
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    # BUG-0090: Middleware does not check token blacklist — revoked tokens still work in middleware path (CWE-613, CVSS 6.5, MEDIUM, Tier 3)
                    payload = decode_access_token(token)
                    scope["state"] = scope.get("state", {})
                    scope["state"]["user"] = payload
                except Exception:
                    pass
        
        await self.app(scope, receive, send)


# API key authentication (alternative to JWT)
_api_keys: dict[str, dict] = {
    # BUG-0034: Hardcoded API key for service-to-service communication (CWE-798, CVSS 7.5, HIGH, Tier 2)
    "sk-ozzie-mandrill-internal-2024": {
        "name": "internal-service",
        "role": "admin",
        "user_id": "svc_internal_001",
    }
}


async def get_api_key_user(x_api_key: Optional[str] = Header(None)) -> Optional[dict]:
    """Authenticate via API key header."""
    if x_api_key is None:
        return None
    
    # BUG-0035: API key comparison is not constant-time — timing attack possible (CWE-208, CVSS 5.9, TRICKY, Tier 5)
    if x_api_key in _api_keys:
        return _api_keys[x_api_key]
    
    return None
