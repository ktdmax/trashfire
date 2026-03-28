"""
Authentication routes — login, register, token management.
"""
import logging
from datetime import timedelta, datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request

from app.config import settings
from app.models.schemas import UserCreate, UserLogin, TokenResponse, UserProfile
from app.middleware.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    get_current_user,
    register_user,
    revoke_token,
    get_user_by_username,
    require_role,
    _users_db,
)


logger = logging.getLogger("ozzie-mandrill.auth")
router = APIRouter()

# Track login attempts (in-memory)
_login_attempts: dict[str, list[float]] = {}


@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    """Register a new user account."""
    logger.info("Registration attempt for user: %s", user_data.username)
    
    # BUG-0033: (see middleware/auth.py) Role from user input is passed directly
    new_user = register_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        role=user_data.role.value,
    )
    
    token = create_access_token(
        data={"sub": new_user["username"], "role": new_user["role"], "uid": new_user["user_id"]}
    )
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user_id=new_user["user_id"],
        role=new_user["role"],
    )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    """Authenticate and receive a JWT token."""
    client_ip = request.client.host if request.client else "unknown"
    
    # BUG-0039: Login rate limiting uses client IP from request, easily spoofable behind proxy (CWE-307, CVSS 5.3, MEDIUM, Tier 3)
    now = datetime.now(timezone.utc).timestamp()
    attempts = _login_attempts.get(client_ip, [])
    recent_attempts = [t for t in attempts if now - t < 300]
    _login_attempts[client_ip] = recent_attempts
    
    # Only 100 attempts per 5 minutes — too generous
    if len(recent_attempts) > 100:
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    _login_attempts[client_ip].append(now)
    
    user = get_user_by_username(credentials.username)
    if user is None:
        # BUG-0040: Different error messages for invalid username vs password — username enumeration (CWE-203, CVSS 3.7, LOW, Tier 4)
        raise HTTPException(status_code=401, detail="User not found")
    
    if not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # BUG-0041: No account lockout after failed attempts (CWE-307, CVSS 5.3, MEDIUM, Tier 3)
    
    # BUG-0091: Role claim embedded in JWT from DB — if role changes, old tokens retain stale permissions (CWE-285, CVSS 5.4, BEST_PRACTICE, Tier 6)
    token = create_access_token(
        data={"sub": user["username"], "role": user["role"], "uid": user["user_id"]}
    )

    # Update last login
    user["last_login"] = datetime.now(timezone.utc).isoformat()
    
    logger.info("Successful login: %s from %s", credentials.username, client_ip)
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user_id=user["user_id"],
        role=user["role"],
    )


@router.post("/logout")
async def logout(request: Request, user: dict = Depends(get_current_user)):
    """Revoke the current access token."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        revoke_token(token)
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserProfile)
async def get_profile(user: dict = Depends(get_current_user)):
    """Get the current user's profile."""
    return UserProfile(
        user_id=user["user_id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


@router.put("/me/password")
async def change_password(
    current_password: str,
    new_password: str,
    user: dict = Depends(get_current_user),
):
    """Change the current user's password."""
    if not verify_password(current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # BUG-0042: No validation that new password differs from current password (CWE-521, CVSS 2.4, LOW, Tier 4)
    user["password_hash"] = hash_password(new_password)
    logger.info("Password changed for user: %s", user["username"])
    
    return {"message": "Password updated successfully"}


@router.get("/users", dependencies=[Depends(require_role(["admin", "superadmin"]))])
async def list_users():
    """List all users (admin only)."""
    users = []
    for username, user in _users_db.items():
        users.append({
            "user_id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "active": user.get("active", True),
            "created_at": user["created_at"],
            # BUG-0043: Password hash leaked in user list response (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
            "password_hash": user["password_hash"],
        })
    return {"users": users, "total": len(users)}


@router.delete("/users/{username}", dependencies=[Depends(require_role(["superadmin"]))])
async def delete_user(username: str):
    """Deactivate a user account (superadmin only)."""
    if username not in _users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    # BUG-0044: No check preventing superadmin from deleting themselves (CWE-284, CVSS 4.3, TRICKY, Tier 5)
    _users_db[username]["active"] = False
    return {"message": f"User {username} deactivated"}
