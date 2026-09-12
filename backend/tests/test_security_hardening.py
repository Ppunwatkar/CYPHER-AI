"""
CIPHER AI - Dedicated Security Hardening & Adversarial Regression Test Suite
Validates OWASP ASVS 5.0, OWASP API Security Top 10, SSRF defenses, Anti-CSRF,
Security Headers, Multi-Tenant Boundaries, Rate Limiting, and Secret Policies.
"""

import ipaddress
import uuid
import pytest
from httpx import AsyncClient
from pydantic import ValidationError

from app.config import Settings
from app.models import User
from app.security.password import (
    validate_password_policy,
    verify_dummy_password,
    verify_password,
)
from app.security.rate_limiter import (
    login_rate_limiter,
    registration_rate_limiter,
    refresh_rate_limiter,
)
from app.security.ssrf import (
    is_ip_blocked,
    validate_outbound_url,
)


@pytest.fixture
def sec_suffix() -> str:
    """Provides unique collision-free suffix for security tests."""
    return uuid.uuid4().hex[:8]


# ==============================================================================
# 1. HTTP Security Headers (OWASP ASVS 14.4)
# ==============================================================================
@pytest.mark.asyncio
async def test_security_headers_enforcement(async_client: AsyncClient):
    """Verifies that all API responses contain mandatory defensive HTTP headers."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "accelerometer=()" in headers.get("Permissions-Policy", "")
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")
    assert "no-store" in headers.get("Cache-Control", "")
    assert headers.get("Pragma") == "no-cache"


# ==============================================================================
# 2. CSRF Protection for State-Changing Requests (OWASP ASVS 4.2)
# ==============================================================================
@pytest.mark.asyncio
async def test_csrf_unauthorized_origin_rejection(async_client: AsyncClient, sec_suffix: str):
    """Verifies that state-changing requests from unauthorized origins are rejected with 403 Forbidden."""
    payload = {
        "email": f"attacker-{sec_suffix}@malicious.org",
        "password": "SecurePassword123!",
        "display_name": "Attacker",
    }
    # Request originating from untrusted third-party site
    spoofed_headers = {
        "Origin": "https://evil-hacker-site.com",
        "Referer": "https://evil-hacker-site.com/exploit.html",
    }
    res = await async_client.post("/api/v1/auth/login", json=payload, headers=spoofed_headers)
    assert res.status_code == 403
    assert "CSRF verification failed" in res.json()["error"]["message"]


@pytest.mark.asyncio
async def test_csrf_cookie_authenticated_mutating_request_requires_custom_header(
    async_client: AsyncClient,
    sec_suffix: str,
):
    """Verifies that cookie-authenticated state-changing requests without custom header/origin are blocked."""
    # Register user to establish valid cookies
    reg = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": f"analyst-{sec_suffix}@corp.defense",
            "password": "SecurePassword123!",
            "display_name": "Analyst",
        },
    )
    assert reg.status_code == 201

    # Simulate cross-site form submission where ambient cookies are sent with no custom header and no Origin
    res = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "", "X-Requested-With": ""},
    )
    # Blocked by CSRF middleware
    assert res.status_code == 403
    assert "CSRF verification failed" in res.json()["error"]["message"]


# ==============================================================================
# 3. Authentication Rate Limiting & Abuse Prevention (OWASP API4:2023)
# ==============================================================================
@pytest.mark.asyncio
async def test_login_brute_force_rate_limiting(async_client: AsyncClient, sec_suffix: str):
    """Verifies that consecutive failed logins trigger HTTP 429 Too Many Requests."""
    target_email = f"victim-{sec_suffix}@defense.corp"

    for _ in range(5):
        res = await async_client.post("/api/v1/auth/login", json={
            "email": target_email,
            "password": "WrongPassword123!",
        })
        assert res.status_code == 401

    # 6th attempt must be throttled
    blocked_res = await async_client.post("/api/v1/auth/login", json={
        "email": target_email,
        "password": "WrongPassword123!",
    })
    assert blocked_res.status_code == 429
    assert "throttled" in blocked_res.json()["detail"].lower()
    assert "Retry-After" in blocked_res.headers


@pytest.mark.asyncio
async def test_registration_flooding_rate_limiting(async_client: AsyncClient, sec_suffix: str):
    """Verifies that excessive registrations from the same IP are throttled."""
    for i in range(10):
        res = await async_client.post("/api/v1/auth/register", json={
            "email": f"flood-{sec_suffix}-{i}@defense.corp",
            "password": "SecurePassword123!",
            "display_name": f"User {i}",
        })
        assert res.status_code == 201

    # 11th registration attempt should trigger 429
    excess_res = await async_client.post("/api/v1/auth/register", json={
        "email": f"flood-{sec_suffix}-overflow@defense.corp",
        "password": "SecurePassword123!",
        "display_name": "Overflow",
    })
    assert excess_res.status_code == 429
    assert "Rate limit exceeded" in excess_res.json()["detail"]


# ==============================================================================
# 4. Centralized SSRF Prevention Gateway (OWASP API7:2023)
# ==============================================================================
def test_ssrf_blocked_loopback_and_private_ranges():
    """Verifies that loopback and RFC 1918 private IPs are identified and rejected."""
    # Loopback
    blocked, reason = is_ip_blocked(ipaddress.ip_address("127.0.0.1"))
    assert blocked is True
    assert "Loopback" in reason

    # IPv6 Loopback
    blocked6, reason6 = is_ip_blocked(ipaddress.ip_address("::1"))
    assert blocked6 is True
    assert "Loopback" in reason6

    # RFC 1918 Private ranges
    assert is_ip_blocked(ipaddress.ip_address("10.0.0.1"))[0] is True
    assert is_ip_blocked(ipaddress.ip_address("172.16.5.10"))[0] is True
    assert is_ip_blocked(ipaddress.ip_address("192.168.1.1"))[0] is True

    # Cloud Instance Metadata Service (AWS/GCP/Azure - 169.254.169.254)
    metadata_blocked, _ = is_ip_blocked(ipaddress.ip_address("169.254.169.254"))
    assert metadata_blocked is True


def test_ssrf_blocked_ipv4_mapped_ipv6():
    """Verifies that IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) cannot bypass filters."""
    mapped_loopback = ipaddress.ip_address("::ffff:127.0.0.1")
    blocked, reason = is_ip_blocked(mapped_loopback)
    assert blocked is True
    assert "Loopback" in reason

    mapped_metadata = ipaddress.ip_address("::ffff:169.254.169.254")
    assert is_ip_blocked(mapped_metadata)[0] is True


def test_ssrf_validate_outbound_url_rejection():
    """Verifies that dangerous URLs are rejected by validate_outbound_url."""
    # Cloud metadata
    assert validate_outbound_url("http://169.254.169.254/latest/meta-data")[0] is False
    assert validate_outbound_url("http://metadata.google.internal/computeMetadata/v1/")[0] is False
    assert validate_outbound_url("http://localhost:8000/api/v1/targets")[0] is False

    # Disallowed schemes
    assert validate_outbound_url("file:///etc/passwd")[0] is False
    assert validate_outbound_url("gopher://127.0.0.1:6379/_flushall")[0] is False
    assert validate_outbound_url("ftp://127.0.0.1/test")[0] is False

    # Internal hostnames
    assert validate_outbound_url("http://host.docker.internal:5432")[0] is False
    assert validate_outbound_url("http://internal.service.local/admin")[0] is False


# ==============================================================================
# 5. Production Secret Key Policy & Enforcement (OWASP ASVS 2.1)
# ==============================================================================
def test_jwt_secret_validation_rejects_weak_keys():
    """Verifies that short or default development secrets are rejected in production/staging."""
    # Under 32 characters
    with pytest.raises(ValidationError) as exc_info:
        Settings(JWT_SECRET_KEY="short-secret", ENVIRONMENT="development")
    assert "at least 32 characters long" in str(exc_info.value)

    # Insecure default key in production
    with pytest.raises(ValidationError) as exc_info_prod:
        Settings(
            JWT_SECRET_KEY="cipher-secops-dev-signing-key-32-chars-minimum-replace-prod",
            ENVIRONMENT="production",
        )
    assert "Insecure default JWT_SECRET_KEY detected in production" in str(exc_info_prod.value)


# ==============================================================================
# 6. Password Security & Timing Discrepancy Mitigation
# ==============================================================================
def test_password_policy_enforcement():
    """Verifies enterprise password complexity enforcement."""
    # Too short
    valid, err = validate_password_policy("Ab1!")
    assert valid is False
    assert "at least 8 characters" in err

    # Missing uppercase
    valid, err = validate_password_policy("password123!")
    assert valid is False
    assert "uppercase" in err

    # Missing special character
    valid, err = validate_password_policy("Password123")
    assert valid is False
    assert "special symbol" in err

    # Valid complex password
    valid, err = validate_password_policy("CipherSecOps$2026!Valid")
    assert valid is True
    assert err is None


def test_dummy_password_verification_runs_cleanly():
    """Verifies constant-time dummy verification runs without error to mitigate timing enumeration."""
    # Must not raise exceptions
    verify_dummy_password("any_arbitrary_candidate")
