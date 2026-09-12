"""
CIPHER AI - Authentication & Authorization Dependencies
FastAPI dependency injection verifying identity tokens, organization binding, and RBAC permissions.
"""

from typing import Callable, Optional
import uuid

from fastapi import Depends, HTTPException, Request, status
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.session import get_db
from app.models import ClearanceLevel, Role, User, UserStatus
from app.security.jwt import decode_access_token


def extract_token_from_request(request: Request) -> Optional[str]:
    """
    Extracts access token with RFC 6750 precedence:
    1. 'Authorization: Bearer <token>' header (explicit client credential)
    2. HttpOnly 'access_token' cookie (browser ambient session fallback)
    """
    # 1. Authorization Bearer header (RFC 6750)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            return token

    # 2. HttpOnly cookie
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    return None


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validates identity token from cookie or header and returns authenticated User entity
    with organization and assigned RBAC roles eagerly loaded.
    """
    token = extract_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. No valid session token provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please log in or refresh your token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims.",
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token.",
        )

    stmt = (
        select(User)
        .options(
            selectinload(User.organization),
            selectinload(User.roles).selectinload(Role.permissions),
        )
        .where(User.id == user_id)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with this session no longer exists.",
        )

    if user.status != UserStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or suspended.",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensures that the current user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account.",
        )
    return current_user


def require_clearance(min_level: ClearanceLevel) -> Callable:
    """Factory dependency verifying that the authenticated user possesses required clearance level."""
    async def clearance_dependency(
        user: User = Depends(get_current_active_user),
    ) -> User:
        if not user.has_clearance(min_level):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient security clearance. Required: {min_level.value}, Authorized: {user.clearance_level}",
            )
        return user

    return clearance_dependency


def require_permission(permission_key: str) -> Callable:
    """Factory dependency verifying that the authenticated user has a specific RBAC permission."""
    async def permission_dependency(
        user: User = Depends(get_current_active_user),
    ) -> User:
        if not user.has_permission(permission_key):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Missing required permission: '{permission_key}'",
            )
        return user

    return permission_dependency
