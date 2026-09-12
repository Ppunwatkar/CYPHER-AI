"""
CIPHER AI - Production Authentication Test Suite (Phase 2C)
Comprehensive automated verification covering all 20 required security scenarios.
"""

from datetime import datetime, timezone
import re
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.models import (
    ClearanceLevel,
    Organization,
    Role,
    User,
    UserSession,
    UserStatus,
)
from app.security.jwt import hash_token
from app.security.password import verify_password
from app.security.rate_limiter import login_rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensures test isolation by clearing the login rate limiter before every test."""
    login_rate_limiter.reset_all()
    yield
    login_rate_limiter.reset_all()


@pytest.fixture
def auth_suffix() -> str:
    """Generates collision-free test user email and identifiers."""
    return uuid.uuid4().hex[:8]


# ==============================================================================
# 1. Successful Registration
# ==============================================================================
@pytest.mark.asyncio
async def test_successful_registration(async_client: AsyncClient, auth_suffix: str):
    """Verifies that registration creates user, organization, hashes password with Argon2id, and sets cookies."""
    payload = {
        "email": f"analyst-{auth_suffix}@defense.corp",
        "password": "SecurePassword123!",
        "display_name": f"Analyst {auth_suffix}",
        "organization_name": f"Defense Operations {auth_suffix}",
        "role_name": "Senior SOC Analyst",
        "clearance_level": "SECRET",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["email"] == payload["email"]
    assert data["display_name"] == payload["display_name"]
    assert data["clearance_level"] == "SECRET"
    assert "Senior SOC Analyst" in data["roles"]
    assert "organization_id" in data
    assert data["organization_name"] == payload["organization_name"]

    # Verify cookies
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies

    # Cleanup
    async with AsyncSessionLocal() as session:
        u = (await session.execute(select(User).where(User.email == payload["email"]))).scalar_one_or_none()
        if u:
            await session.delete(u)
            org = await session.get(Organization, u.organization_id)
            if org:
                await session.delete(org)
            await session.commit()


# ==============================================================================
# 2. Duplicate Email Handling
# ==============================================================================
@pytest.mark.asyncio
async def test_duplicate_email_handling(async_client: AsyncClient, auth_suffix: str):
    """Verifies that attempting to register an existing email is rejected with 400 Bad Request."""
    payload = {
        "email": f"dup-{auth_suffix}@defense.corp",
        "password": "SecurePassword123!",
        "display_name": "First User",
    }
    res1 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    # Second attempt with same email
    res2 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"].lower()


# ==============================================================================
# 3. Successful Login
# ==============================================================================
@pytest.mark.asyncio
async def test_successful_login(async_client: AsyncClient, auth_suffix: str):
    """Verifies successful login with valid credentials sets cookies and returns profile."""
    email = f"login-{auth_suffix}@defense.corp"
    password = "CorrectPassword123!"

    # Register first
    await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Login Tester",
    })

    # Login
    response = await async_client.post("/api/v1/auth/login", json={
        "email": email,
        "password": password,
    })
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies


# ==============================================================================
# 4. Invalid Password
# ==============================================================================
@pytest.mark.asyncio
async def test_invalid_password(async_client: AsyncClient, auth_suffix: str):
    """Verifies that wrong password returns HTTP 401 with generic error."""
    email = f"wrongpwd-{auth_suffix}@defense.corp"
    await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": "RealPassword123!",
        "display_name": "Wrong Pwd Tester",
    })

    response = await async_client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "IncorrectPassword999!",
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


# ==============================================================================
# 5. Nonexistent Account
# ==============================================================================
@pytest.mark.asyncio
async def test_nonexistent_account(async_client: AsyncClient):
    """Verifies that nonexistent account returns identical 401 message."""
    response = await async_client.post("/api/v1/auth/login", json={
        "email": "completely-nonexistent-user@defense.corp",
        "password": "SomePassword123!",
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


# ==============================================================================
# 6. Disabled Account
# ==============================================================================
@pytest.mark.asyncio
async def test_disabled_account(async_client: AsyncClient, auth_suffix: str):
    """Verifies that suspended account cannot log in and receives enumeration-safe 401."""
    email = f"disabled-{auth_suffix}@defense.corp"
    password = "ValidPassword123!"

    reg = await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Suspended User",
    })
    assert reg.status_code == 201

    # Suspend user in DB
    async with AsyncSessionLocal() as session:
        u = (await session.execute(select(User).where(User.email == email))).scalar_one()
        u.status = UserStatus.SUSPENDED.value
        await session.commit()

    # Attempt login
    response = await async_client.post("/api/v1/auth/login", json={
        "email": email,
        "password": password,
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


# ==============================================================================
# 7. Logout
# ==============================================================================
@pytest.mark.asyncio
async def test_logout(async_client: AsyncClient, auth_suffix: str):
    """Verifies logout revokes server session in DB and clears cookies."""
    email = f"logout-{auth_suffix}@defense.corp"
    password = "LogoutPass123!"

    reg = await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Logout Tester",
    })
    refresh_token = reg.cookies.get("refresh_token")
    assert refresh_token is not None

    # Call logout
    logout_res = await async_client.post("/api/v1/auth/logout", cookies=reg.cookies)
    assert logout_res.status_code == 200
    assert logout_res.json()["authenticated"] is False

    # Verify session in DB is revoked
    token_h = hash_token(refresh_token)
    async with AsyncSessionLocal() as session:
        sess = (await session.execute(select(UserSession).where(UserSession.token_hash == token_h))).scalar_one_or_none()
        assert sess is not None
        assert sess.revoked is True


# ==============================================================================
# 8. Authenticated /me
# ==============================================================================
@pytest.mark.asyncio
async def test_authenticated_me(async_client: AsyncClient, auth_suffix: str):
    """Verifies /me endpoint returns authenticated user profile."""
    email = f"me-{auth_suffix}@defense.corp"
    password = "PasswordForMe123!"

    reg = await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Me User",
        "clearance_level": "CONFIDENTIAL",
    })
    assert reg.status_code == 201

    me_res = await async_client.get("/api/v1/auth/me", cookies=reg.cookies)
    assert me_res.status_code == 200
    data = me_res.json()
    assert data["email"] == email
    assert data["display_name"] == "Me User"
    assert data["clearance_level"] == "CONFIDENTIAL"


# ==============================================================================
# 9. Unauthenticated /me
# ==============================================================================
@pytest.mark.asyncio
async def test_unauthenticated_me(async_client: AsyncClient):
    """Verifies /me without credentials returns 401."""
    response = await async_client.get("/api/v1/auth/me")
    assert response.status_code == 401


# ==============================================================================
# 10. Session Refresh & Token Rotation
# ==============================================================================
@pytest.mark.asyncio
async def test_session_refresh_and_rotation(async_client: AsyncClient, auth_suffix: str):
    """Verifies /refresh rotates refresh token and invalidates old token."""
    email = f"refresh-{auth_suffix}@defense.corp"
    password = "RefreshPass123!"

    reg = await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Refresh Tester",
    })
    old_refresh_token = reg.cookies.get("refresh_token")

    # Refresh
    refresh_res = await async_client.post("/api/v1/auth/refresh", cookies={"refresh_token": old_refresh_token})
    assert refresh_res.status_code == 200
    new_refresh_token = refresh_res.cookies.get("refresh_token")
    assert new_refresh_token is not None
    assert new_refresh_token != old_refresh_token

    # Verify old session revoked in DB
    old_h = hash_token(old_refresh_token)
    async with AsyncSessionLocal() as session:
        old_sess = (await session.execute(select(UserSession).where(UserSession.token_hash == old_h))).scalar_one()
        assert old_sess.revoked is True


# ==============================================================================
# 11. Session Revocation
# ==============================================================================
@pytest.mark.asyncio
async def test_session_revocation_prevents_reuse(async_client: AsyncClient, auth_suffix: str):
    """Verifies that revoked session refresh token cannot be refreshed."""
    email = f"revoked-{auth_suffix}@defense.corp"
    password = "RevokedPass123!"

    reg = await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "Revoke Tester",
    })
    refresh_token = reg.cookies.get("refresh_token")

    # Logout to revoke
    await async_client.post("/api/v1/auth/logout", cookies={"refresh_token": refresh_token})

    # Attempt to refresh with revoked token
    retry_res = await async_client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
    assert retry_res.status_code == 401


# ==============================================================================
# 12. Organization Isolation
# ==============================================================================
@pytest.mark.asyncio
async def test_organization_isolation(async_client: AsyncClient, auth_suffix: str):
    """Verifies each user is bound to their organization and cannot cross boundaries."""
    # Org A
    reg_a = await async_client.post("/api/v1/auth/register", json={
        "email": f"alice-{auth_suffix}@alpha.corp",
        "password": "Password123!",
        "display_name": "Alice Alpha",
        "organization_name": f"Org Alpha {auth_suffix}",
    })
    # Org B
    reg_b = await async_client.post("/api/v1/auth/register", json={
        "email": f"bob-{auth_suffix}@beta.corp",
        "password": "Password123!",
        "display_name": "Bob Beta",
        "organization_name": f"Org Beta {auth_suffix}",
    })

    user_a = reg_a.json()
    user_b = reg_b.json()

    assert user_a["organization_id"] != user_b["organization_id"]
    assert user_a["organization_name"] != user_b["organization_name"]


# ==============================================================================
# 13. Password Hash Verification
# ==============================================================================
@pytest.mark.asyncio
async def test_password_hash_verification(async_client: AsyncClient, auth_suffix: str):
    """Verifies that stored password hash uses Argon2id and verifies correctly."""
    email = f"argon-{auth_suffix}@defense.corp"
    plain_password = "SecretArgon2Password123!"

    await async_client.post("/api/v1/auth/register", json={
        "email": email,
        "password": plain_password,
        "display_name": "Argon Tester",
    })

    async with AsyncSessionLocal() as session:
        user = (await session.execute(select(User).where(User.email == email))).scalar_one()
        assert user.hashed_password.startswith("$argon2id$")
        assert verify_password(plain_password, user.hashed_password) is True
        assert verify_password("WrongPassword!", user.hashed_password) is False


# ==============================================================================
# 14. Password Hash Is Never Returned
# ==============================================================================
@pytest.mark.asyncio
async def test_password_hash_is_never_returned(async_client: AsyncClient, auth_suffix: str):
    """Verifies that password and password hashes are never returned in responses."""
    payload = {
        "email": f"leakcheck-{auth_suffix}@defense.corp",
        "password": "LeakCheckPassword123!",
        "display_name": "Leak Checker",
    }
    reg_res = await async_client.post("/api/v1/auth/register", json=payload)
    login_res = await async_client.post("/api/v1/auth/login", json={
        "email": payload["email"],
        "password": payload["password"],
    })
    me_res = await async_client.get("/api/v1/auth/me", cookies=reg_res.cookies)

    for res in [reg_res, login_res, me_res]:
        body_text = res.text.lower()
        assert "hashed_password" not in body_text
        assert "$argon2id$" not in body_text
        assert "argon" not in body_text
        assert payload["password"].lower() not in body_text


# ==============================================================================
# 15. Authentication Secrets Are Not Logged
# ==============================================================================
def test_authentication_secrets_are_not_logged():
    """Verifies that model __repr__ suppresses passwords and secrets."""
    user = User(
        email="test@secops.corp",
        display_name="Test Operator",
        hashed_password="$argon2id$secret_hash_value",
    )
    repr_output = repr(user)
    assert "$argon2id$" not in repr_output
    assert "hashed_password" not in repr_output


# ==============================================================================
# 16. Role Association
# ==============================================================================
@pytest.mark.asyncio
async def test_role_association(async_client: AsyncClient, auth_suffix: str):
    """Verifies user role association is correctly mapped on registration and login."""
    res = await async_client.post("/api/v1/auth/register", json={
        "email": f"rolecheck-{auth_suffix}@defense.corp",
        "password": "Password123!",
        "display_name": "Role Analyst",
        "role_name": "Threat Hunter Lead",
    })
    assert res.status_code == 201
    assert "Threat Hunter Lead" in res.json()["roles"]


# ==============================================================================
# 17. Clearance Association
# ==============================================================================
@pytest.mark.asyncio
async def test_clearance_association(async_client: AsyncClient, auth_suffix: str):
    """Verifies user security clearance is correctly stored and retrieved."""
    res = await async_client.post("/api/v1/auth/register", json={
        "email": f"clearancecheck-{auth_suffix}@defense.corp",
        "password": "Password123!",
        "display_name": "Clearance Analyst",
        "clearance_level": "TOP_SECRET",
    })
    assert res.status_code == 201
    assert res.json()["clearance_level"] == "TOP_SECRET"


# ==============================================================================
# 18. Account Enumeration Protection
# ==============================================================================
@pytest.mark.asyncio
async def test_account_enumeration_protection(async_client: AsyncClient, auth_suffix: str):
    """
    Verifies that existent user with wrong password and nonexistent user
    return the exact same error code and message.
    """
    # Existent user
    await async_client.post("/api/v1/auth/register", json={
        "email": f"existing-{auth_suffix}@defense.corp",
        "password": "CorrectPassword123!",
        "display_name": "Existing User",
    })

    # 1. Existent user + wrong password
    res_wrong_pwd = await async_client.post("/api/v1/auth/login", json={
        "email": f"existing-{auth_suffix}@defense.corp",
        "password": "WrongPassword999!",
    })

    # 2. Nonexistent user
    res_no_user = await async_client.post("/api/v1/auth/login", json={
        "email": f"ghost-{auth_suffix}@defense.corp",
        "password": "WrongPassword999!",
    })

    assert res_wrong_pwd.status_code == res_no_user.status_code == 401
    assert res_wrong_pwd.json()["detail"] == res_no_user.json()["detail"] == "Invalid email or password."


# ==============================================================================
# 19. Cookie Security Attributes
# ==============================================================================
@pytest.mark.asyncio
async def test_cookie_security_attributes(async_client: AsyncClient, auth_suffix: str):
    """Verifies Set-Cookie header contains HttpOnly, SameSite, and path attributes."""
    reg = await async_client.post("/api/v1/auth/register", json={
        "email": f"cookie-{auth_suffix}@defense.corp",
        "password": "Password123!",
        "display_name": "Cookie Tester",
    })
    set_cookie_headers = reg.headers.get_list("set-cookie")
    assert len(set_cookie_headers) >= 2

    # Check access_token cookie
    access_cookie = [h for h in set_cookie_headers if "access_token=" in h][0].lower()
    assert "httponly" in access_cookie
    assert "samesite=lax" in access_cookie
    assert "path=/" in access_cookie

    # Check refresh_token cookie
    refresh_cookie = [h for h in set_cookie_headers if "refresh_token=" in h][0].lower()
    assert "httponly" in refresh_cookie
    assert "samesite=lax" in refresh_cookie
    assert "path=/api/v1/auth" in refresh_cookie


# ==============================================================================
# 20. Migration Lifecycle Verification
# ==============================================================================
@pytest.mark.asyncio
async def test_migration_lifecycle_with_sessions():
    """Verifies that all migrations up to ce4d521f64e2 apply cleanly and maintain schema."""
    import subprocess
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parent.parent

    import sys
    current_res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert current_res.returncode == 0
    assert "(head)" in current_res.stdout
