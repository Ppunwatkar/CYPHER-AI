"""
CIPHER AI - JWT & Session Token Management
Short-lived access tokens and cryptographic refresh tokens with SHA-256 database hashing.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple
import uuid

import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError, InvalidTokenError

from app.config import get_settings

settings = get_settings()


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 hash of a raw token for database storage and verification."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: Optional[uuid.UUID] = None,
    organization_id: Optional[uuid.UUID] = None,
    clearance: Optional[str] = None,
    roles: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None,
    data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Creates a signed, short-lived JWT access token containing identity claims.
    Supports either explicit parameters or a custom claim dictionary.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    sub_val = str(user_id) if user_id else ""
    org_val = str(organization_id) if organization_id else ""
    clearance_val = clearance or "UNCLASSIFIED"
    roles_val = roles or []

    payload: Dict[str, Any] = {
        "sub": sub_val,
        "org_id": org_val,
        "clearance": clearance_val,
        "roles": roles_val,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "type": "access",
    }

    if data:
        if "sub" in data:
            payload["sub"] = str(data["sub"])
        if "org" in data:
            payload["org_id"] = str(data["org"])
        if "org_id" in data:
            payload["org_id"] = str(data["org_id"])
        if "clearance" in data:
            payload["clearance"] = str(data["clearance"])
        if "roles" in data:
            payload["roles"] = data["roles"]
        for k, v in data.items():
            if k not in ("sub", "org", "org_id", "clearance", "roles"):
                payload[k] = v

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token() -> Tuple[str, str, datetime]:
    """
    Generates a cryptographically secure random refresh token.
    Returns:
        tuple of (raw_token: str, token_hash: str, expires_at: datetime)
    """
    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return raw_token, token_hash, expires_at


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token.
    Raises ExpiredSignatureError or InvalidTokenError if invalid.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "sub", "org_id"]},
    )
