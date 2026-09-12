"""
CIPHER AI - Production Authentication API Endpoints
Implements register, login, logout, refresh, and current user (/me) endpoints
with Argon2id hashing, HttpOnly cookies, token rotation, and brute-force protection.
"""

from datetime import datetime, timezone
import re
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database.session import get_db
from app.models import (
    ClearanceLevel,
    Organization,
    OrganizationStatus,
    Permission,
    Role,
    User,
    UserSession,
    UserStatus,
)
from app.schemas.auth import (
    AuthStatusResponse,
    LoginRequest,
    RegisterRequest,
    UserAuthResponse,
)
from app.security.deps import get_current_active_user
from app.security.jwt import (
    create_access_token,
    create_refresh_token,
    hash_token,
)
from app.security.password import (
    hash_password,
    verify_dummy_password,
    verify_password,
)
from app.security.rate_limiter import (
    login_rate_limiter,
    registration_rate_limiter,
    refresh_rate_limiter,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


def _format_user_auth_response(user: User) -> UserAuthResponse:
    """Transforms User ORM entity into sanitized UserAuthResponse schema."""
    role_names: List[str] = [r.name for r in user.roles] if user.roles else []
    permissions_set = set()
    if user.roles:
        for r in user.roles:
            if r.permissions:
                for p in r.permissions:
                    permissions_set.add(p.key)

    org_name = user.organization.name if user.organization else "SecOps Organization"

    return UserAuthResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        organization_id=user.organization_id,
        organization_name=org_name,
        status=user.status,
        clearance_level=user.clearance_level,
        roles=role_names,
        permissions=sorted(list(permissions_set)),
        created_at=user.created_at,
    )


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    """Attaches secure HttpOnly cookies for access and refresh tokens."""
    access_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400

    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=access_max_age,
        expires=access_max_age,
        httponly=True,
        secure=settings.is_cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        path="/",
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=refresh_max_age,
        expires=refresh_max_age,
        httponly=True,
        secure=settings.is_cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        path="/api/v1/auth",
    )


def _clear_auth_cookies(response: Response) -> None:
    """Explicitly deletes authentication cookies with matching paths."""
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        secure=settings.is_cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
    )
    response.delete_cookie(
        key="refresh_token",
        path="/api/v1/auth",
        httponly=True,
        secure=settings.is_cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
    )


def _slugify(text: str) -> str:
    """Generates a clean URL slug from organization name."""
    clean = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", clean) or "organization"


DEFAULT_OPERATIONAL_PERMISSIONS = [
    ("targets:read", "Read Targets", "View security targets and observables"),
    ("targets:create", "Create Targets", "Create security targets and observables"),
    ("targets:update", "Update Targets", "Modify security targets and observables"),
    ("targets:delete", "Delete Targets", "Delete security targets and observables"),
]


async def _ensure_default_permissions(db: AsyncSession, role: Role) -> None:
    """Ensures operational permissions exist and are assigned to the analyst role without lazy load."""
    from app.models.role import role_permissions
    from sqlalchemy import insert

    for key, name, desc in DEFAULT_OPERATIONAL_PERMISSIONS:
        stmt = select(Permission).where(Permission.key == key)
        perm = (await db.execute(stmt)).scalar_one_or_none()
        if not perm:
            perm = Permission(key=key, name=name, description=desc)
            db.add(perm)
            await db.flush()

        check_stmt = select(role_permissions.c.role_id).where(
            (role_permissions.c.role_id == role.id)
            & (role_permissions.c.permission_id == perm.id)
        )
        if not (await db.execute(check_stmt)).first():
            await db.execute(
                insert(role_permissions).values(role_id=role.id, permission_id=perm.id)
            )
    await db.flush()


@router.post(
    "/register",
    response_model=UserAuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Security Analyst",
    description="Registers a new analyst account with Argon2id password encryption, organization binding, and session establishment.",
)
async def register(
    req: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> UserAuthResponse:
    """Handles operator registration with tenant association and session establishment."""
    # 0. Rate limiting check
    client_ip = request.client.host if request.client else "127.0.0.1"
    registration_rate_limiter.check_and_record(client_ip)

    # 1. Check for existing email to prevent duplicate accounts
    existing_stmt = select(User).where(User.email == req.email)
    existing_res = await db.execute(existing_stmt)
    if existing_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in or use a different address.",
        )

    # 2. Find or create tenant Organization
    org_name = (req.organization_name or "Global SOC Sentinel Unit").strip()
    org_slug = _slugify(org_name)

    org_stmt = select(Organization).where(Organization.slug == org_slug)
    org_res = await db.execute(org_stmt)
    org = org_res.scalar_one_or_none()

    if not org:
        org = Organization(
            name=org_name,
            slug=org_slug,
            status=OrganizationStatus.ACTIVE.value,
        )
        db.add(org)
        await db.flush()

    # 3. Find or create initial Role
    role_name = (req.role_name or "Incident Responder").strip()
    role_stmt = select(Role).where(
        (Role.organization_id == org.id) & (Role.name == role_name)
    )
    role_res = await db.execute(role_stmt)
    role = role_res.scalar_one_or_none()

    if not role:
        role = Role(
            organization_id=org.id,
            name=role_name,
            description=f"{role_name} for {org.name}",
        )
        db.add(role)
        await db.flush()

    # Ensure role has operational target permissions
    await _ensure_default_permissions(db, role)

    # 4. Hash password with Argon2id
    pwd_hash = hash_password(req.password)

    # 5. Create User entity
    clearance_val = req.clearance_level.value if req.clearance_level else ClearanceLevel.UNCLASSIFIED.value
    user = User(
        organization_id=org.id,
        email=req.email,
        display_name=req.display_name,
        hashed_password=pwd_hash,
        status=UserStatus.ACTIVE.value,
        clearance_level=clearance_val,
        roles=[role],
    )
    db.add(user)
    await db.flush()

    # 6. Establish Session & Tokens
    raw_refresh, token_hash, expires_at = create_refresh_token()
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")[:255]

    session_record = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    db.add(session_record)
    await db.commit()

    # Refresh user with relationships loaded
    loaded_stmt = (
        select(User)
        .options(
            selectinload(User.organization),
            selectinload(User.roles).selectinload(Role.permissions),
        )
        .where(User.id == user.id)
    )
    loaded_user = (await db.execute(loaded_stmt)).scalar_one()

    # Create Access Token and set cookies
    access_token = create_access_token(
        user_id=loaded_user.id,
        organization_id=loaded_user.organization_id,
        clearance=loaded_user.clearance_level,
        roles=[r.name for r in loaded_user.roles],
    )
    _set_auth_cookies(response, access_token, raw_refresh)

    return _format_user_auth_response(loaded_user)


@router.post(
    "/login",
    response_model=UserAuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst Login",
    description="Authenticates credentials against Argon2id hash with rate-limiting, timing-attack protection, and sets HttpOnly cookies.",
)
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> UserAuthResponse:
    """Authenticates credentials and establishes session."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Check rate limit
    login_rate_limiter.check_rate_limit(client_ip)

    # 2. Query user by email
    stmt = (
        select(User)
        .options(
            selectinload(User.organization),
            selectinload(User.roles).selectinload(Role.permissions),
        )
        .where(User.email == req.email)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # 3. Account Enumeration & Timing Attack Defense
    if not user:
        # Execute constant-time dummy verification
        verify_dummy_password(req.password)
        login_rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Verify password with Argon2id
    is_password_valid = verify_password(req.password, user.hashed_password)
    if not is_password_valid:
        login_rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Verify user status
    if user.status != UserStatus.ACTIVE.value:
        login_rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",  # Same generic error prevents status enumeration
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 6. Reset rate limit counter on success
    login_rate_limiter.record_success(client_ip)

    # 7. Create server-side session and tokens
    raw_refresh, token_hash, expires_at = create_refresh_token()
    user_agent = request.headers.get("user-agent", "")[:255]

    session_record = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    db.add(session_record)
    await db.commit()

    # 8. Set HttpOnly cookies
    access_token = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        clearance=user.clearance_level,
        roles=[r.name for r in user.roles],
    )
    _set_auth_cookies(response, access_token, raw_refresh)

    return _format_user_auth_response(user)


@router.post(
    "/logout",
    response_model=AuthStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Sign Out Analyst Session",
    description="Revokes server-side session in database and clears authentication cookies.",
)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AuthStatusResponse:
    """Revokes session and clears client cookies."""
    raw_refresh = request.cookies.get("refresh_token")
    if raw_refresh:
        token_h = hash_token(raw_refresh)
        stmt = select(UserSession).where(UserSession.token_hash == token_h)
        sess = (await db.execute(stmt)).scalar_one_or_none()
        if sess:
            sess.revoked = True
            await db.commit()

    _clear_auth_cookies(response)
    return AuthStatusResponse(
        message="Session revoked successfully. Analyst signed out.",
        authenticated=False,
    )


@router.post(
    "/refresh",
    response_model=UserAuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh Session Credentials",
    description="Validates HttpOnly refresh token cookie, performs token rotation, and issues fresh credentials.",
)
async def refresh_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> UserAuthResponse:
    """Rotates refresh token and issues fresh access token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    refresh_rate_limiter.check_and_record(client_ip)

    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required.",
        )

    token_h = hash_token(raw_refresh)
    now = datetime.now(timezone.utc)

    stmt = (
        select(UserSession)
        .options(
            selectinload(UserSession.user).selectinload(User.organization),
            selectinload(UserSession.user).selectinload(User.roles).selectinload(Role.permissions),
        )
        .where(UserSession.token_hash == token_h)
    )
    sess = (await db.execute(stmt)).scalar_one_or_none()

    if not sess or sess.revoked or sess.expires_at <= now:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was revoked. Please log in again.",
        )

    user = sess.user
    if not user or user.status != UserStatus.ACTIVE.value:
        sess.revoked = True
        await db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is no longer active.",
        )

    # Token Rotation: Revoke current session and issue new pair
    sess.revoked = True

    new_raw_refresh, new_token_hash, new_expires_at = create_refresh_token()
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")[:255]

    new_session = UserSession(
        user_id=user.id,
        token_hash=new_token_hash,
        expires_at=new_expires_at,
        revoked=False,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    db.add(new_session)
    await db.commit()

    # Set new cookies
    new_access_token = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        clearance=user.clearance_level,
        roles=[r.name for r in user.roles],
    )
    _set_auth_cookies(response, new_access_token, new_raw_refresh)

    return _format_user_auth_response(user)


@router.get(
    "/me",
    response_model=UserAuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Current Authenticated Analyst",
    description="Returns identity claims, organization, and clearance of the currently authenticated user.",
)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserAuthResponse:
    """Returns currently authenticated user profile."""
    return _format_user_auth_response(current_user)
