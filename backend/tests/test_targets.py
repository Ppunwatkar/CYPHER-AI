"""
CIPHER AI - Target and Observable Persistence Test Suite (Phase 3)
Comprehensive automated verification covering all 20 required security scenarios.
"""

from datetime import datetime, timezone
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import delete, insert, select

from app.database.session import AsyncSessionLocal
from app.models import (
    AuditLog,
    ClearanceLevel,
    Observable,
    Organization,
    Permission,
    Role,
    SecurityTarget,
    User,
    role_permissions,
    user_roles,
)
from app.services.normalization import (
    auto_detect_type,
    defang_input,
    normalize_cve,
    normalize_domain,
    normalize_hash,
    normalize_indicator,
    normalize_ipv4,
    normalize_ipv6,
    normalize_cidr,
    normalize_url,
)


@pytest.fixture
def test_suffix() -> str:
    """Generates unique suffix for collision-free test entity attributes."""
    return uuid.uuid4().hex[:8]


async def create_authenticated_user(
    async_client: AsyncClient,
    suffix: str,
    org_name: Optional[str] = None,
    role_name: str = "Incident Responder",
) -> Tuple[Dict[str, str], dict]:
    """Registers and authenticates a test operator, returning session cookies and user info."""
    effective_org = org_name or f"SOC Alpha Defense {suffix}"
    payload = {
        "email": f"analyst-{suffix}@soc-{suffix}.internal",
        "password": "SecurePassword123!",
        "display_name": f"Analyst {suffix}",
        "organization_name": effective_org,
        "role_name": role_name,
        "clearance_level": "SECRET",
    }
    res = await async_client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 201
    user_data = res.json()
    cookies = res.cookies
    headers = {"Authorization": f"Bearer {cookies.get('access_token', '')}"}
    return headers, user_data


# ==============================================================================
# 1. Create Target
# ==============================================================================
@pytest.mark.asyncio
async def test_create_target(async_client: AsyncClient, test_suffix: str):
    """Verifies creating a normalized security target within tenant organization."""
    headers, user = await create_authenticated_user(async_client, test_suffix)

    payload = {
        "value": "185[.]220[.]101[.]5:8080",
        "label": "Frankfurt C2 Relay",
        "environment": "external_threat",
        "priority": "critical",
        "threatScore": 92,
        "verdict": "malicious",
        "riskLevel": "CRITICAL",
        "confidence": 94,
        "tags": ["Cobalt Strike", "APT29"],
        "openPorts": [80, 443, 8080],
        "asn": "AS206238",
        "country": "Germany",
        "city": "Frankfurt",
    }
    response = await async_client.post("/api/v1/targets", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()

    assert data["value"] == "185.220.101.5"  # Normalized & defanged
    assert data["type"] == "ipv4"
    assert data["label"] == "Frankfurt C2 Relay"
    assert data["organization_id"] == user["organization_id"]
    assert data["priority"] == "critical"
    assert data["threatScore"] == 92
    assert data["verdict"] == "malicious"
    assert 8080 in data["openPorts"]
    assert "APT29" in data["tags"]


# ==============================================================================
# 2. List Targets
# ==============================================================================
@pytest.mark.asyncio
async def test_list_targets(async_client: AsyncClient, test_suffix: str):
    """Verifies listing targets scoped strictly to user organization with search and filter."""
    headers, user = await create_authenticated_user(async_client, test_suffix)

    # Ingest 2 targets
    await async_client.post(
        "/api/v1/targets",
        json={"value": f"10.240.{(int(test_suffix[:4], 16) % 200) + 1}.1", "label": "K8s Worker Node", "environment": "production"},
        headers=headers,
    )
    await async_client.post(
        "/api/v1/targets",
        json={"value": f"c2-{test_suffix}.azure-edge-sync.net", "label": "Phishing Proxy", "environment": "external_threat"},
        headers=headers,
    )

    # List all
    res = await async_client.get("/api/v1/targets", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert any(t["label"] == "K8s Worker Node" for t in data["items"])

    # Search filter
    search_res = await async_client.get(f"/api/v1/targets?search=Phishing", headers=headers)
    assert search_res.status_code == 200
    search_data = search_res.json()
    assert len(search_data["items"]) >= 1
    assert "Phishing Proxy" in search_data["items"][0]["label"]


# ==============================================================================
# 3. Retrieve Target by ID
# ==============================================================================
@pytest.mark.asyncio
async def test_retrieve_target(async_client: AsyncClient, test_suffix: str):
    """Verifies retrieving a single target by UUID."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    create_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "194.26.29.114", "label": "Mirai Scanner", "environment": "external_threat"},
        headers=headers,
    )
    target_id = create_res.json()["id"]

    get_res = await async_client.get(f"/api/v1/targets/{target_id}", headers=headers)
    assert get_res.status_code == 200
    target_data = get_res.json()
    assert target_data["id"] == target_id
    assert target_data["value"] == "194.26.29.114"


# ==============================================================================
# 4. Update Target
# ==============================================================================
@pytest.mark.asyncio
async def test_update_target(async_client: AsyncClient, test_suffix: str):
    """Verifies partial modification of target fields."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    create_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "10.0.0.1", "label": "Core Gateway", "status": "QUEUED", "threatScore": 20},
        headers=headers,
    )
    target_id = create_res.json()["id"]

    update_payload = {
        "status": "INVESTIGATED",
        "threatScore": 85,
        "verdict": "suspicious",
        "notes": "Elevated traffic observed targeting non-standard port 9001.",
    }
    patch_res = await async_client.patch(f"/api/v1/targets/{target_id}", json=update_payload, headers=headers)
    assert patch_res.status_code == 200
    updated_data = patch_res.json()
    assert updated_data["status"] == "INVESTIGATED"
    assert updated_data["threatScore"] == 85
    assert updated_data["verdict"] == "suspicious"
    assert "9001" in updated_data["notes"]


# ==============================================================================
# 5. Delete Target
# ==============================================================================
@pytest.mark.asyncio
async def test_delete_target(async_client: AsyncClient, test_suffix: str):
    """Verifies deleting a target and cascade cleanup."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    create_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "192.168.1.50", "label": "Temporary Asset"},
        headers=headers,
    )
    target_id = create_res.json()["id"]

    del_res = await async_client.delete(f"/api/v1/targets/{target_id}", headers=headers)
    assert del_res.status_code == 200

    # Ensure 404 on subsequent get
    get_res = await async_client.get(f"/api/v1/targets/{target_id}", headers=headers)
    assert get_res.status_code == 404


# ==============================================================================
# 6. Create Observable
# ==============================================================================
@pytest.mark.asyncio
async def test_create_observable(async_client: AsyncClient, test_suffix: str):
    """Verifies creating an observable linked to a target."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    tgt_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "185.220.101.5", "label": "Host Relay"},
        headers=headers,
    )
    target_id = tgt_res.json()["id"]

    obs_payload = {
        "value": "CVE-2024-38077",
        "type": "cve",
        "source": "Vulnerability Assessment",
        "confidence": 95,
        "severity": "critical",
    }
    obs_res = await async_client.post(f"/api/v1/targets/{target_id}/observables", json=obs_payload, headers=headers)
    assert obs_res.status_code == 201
    obs_data = obs_res.json()
    assert obs_data["value"] == "CVE-2024-38077"
    assert obs_data["type"] == "cve"
    assert obs_data["target_id"] == target_id
    assert obs_data["confidence"] == 95


# ==============================================================================
# 7. List Observables
# ==============================================================================
@pytest.mark.asyncio
async def test_list_observables(async_client: AsyncClient, test_suffix: str):
    """Verifies listing observables associated with a target."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    tgt_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "185.220.101.5", "label": "Relay Host"},
        headers=headers,
    )
    target_id = tgt_res.json()["id"]

    await async_client.post(
        f"/api/v1/targets/{target_id}/observables",
        json={"value": f"beacon-{test_suffix}.c2domain.net", "type": "domain"},
        headers=headers,
    )
    await async_client.post(
        f"/api/v1/targets/{target_id}/observables",
        json={"value": "hxxps://auth-verify[.]net/payload", "type": "url"},
        headers=headers,
    )

    list_res = await async_client.get(f"/api/v1/targets/{target_id}/observables", headers=headers)
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] == 2
    assert any(o["type"] == "domain" for o in list_data["items"])
    assert any(o["type"] == "url" for o in list_data["items"])


# ==============================================================================
# 8. Observable Normalization
# ==============================================================================
def test_observable_normalization():
    """Verifies normalization for IPv4, IPv6, CIDR, domain, URL, hashes, and CVEs."""
    # 1. IPv4 (with defanging and port stripping)
    res_ipv4 = normalize_indicator("185[.]220[.]101[.]5:8080", "ipv4")
    assert res_ipv4.is_valid is True
    assert res_ipv4.normalized_value == "185.220.101.5"

    # 2. IPv6 (with bracket and port stripping)
    res_ipv6 = normalize_indicator("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443", "ipv6")
    assert res_ipv6.is_valid is True
    assert res_ipv6.normalized_value == "2001:db8:85a3::8a2e:370:7334"

    # 3. CIDR (IPv4 and IPv6)
    res_cidr = normalize_indicator("10[.]240[.]0[.]0/16", "cidr")
    assert res_cidr.is_valid is True
    assert res_cidr.normalized_value == "10.240.0.0/16"

    # 4. Domain (lowercasing, scheme and port stripping)
    res_domain = normalize_indicator("HTTPS://Evil-C2[.]Corp.NET:8443/", "domain")
    assert res_domain.is_valid is True
    assert res_domain.normalized_value == "evil-c2.corp.net"

    # 5. URL (defanged protocol, lowercase authority)
    res_url = normalize_indicator("hxxps://Victim-SSO[.]Domain.Cloud/login.php?id=99", "url")
    assert res_url.is_valid is True
    assert res_url.normalized_value == "https://victim-sso.domain.cloud/login.php?id=99"

    # 6. Hashes (MD5, SHA1, SHA256)
    res_md5 = normalize_indicator("5D41402ABC4B2A76B9719D911017C592", "md5")
    assert res_md5.is_valid is True
    assert res_md5.normalized_value == "5d41402abc4b2a76b9719d911017c592"

    res_sha1 = normalize_indicator("2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12", "sha1")
    assert res_sha1.is_valid is True
    assert res_sha1.normalized_value == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

    res_sha256 = normalize_indicator("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256")
    assert res_sha256.is_valid is True
    assert res_sha256.normalized_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # 7. CVE (canonical uppercase)
    res_cve = normalize_indicator("cve-2024-38077", "cve")
    assert res_cve.is_valid is True
    assert res_cve.normalized_value == "CVE-2024-38077"


# ==============================================================================
# 9. Malformed Observable Rejection
# ==============================================================================
@pytest.mark.asyncio
async def test_malformed_observable_rejection(async_client: AsyncClient, test_suffix: str):
    """Verifies that invalid or malformed observables are rejected with 400 Bad Request."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    # Invalid IPv4 (octet > 255)
    res1 = await async_client.post("/api/v1/targets", json={"value": "999.1.1.1", "type": "ipv4"}, headers=headers)
    assert res1.status_code == 400
    assert "validation failed" in res1.json()["detail"].lower()

    # Invalid CIDR prefix (>32)
    res2 = await async_client.post("/api/v1/targets", json={"value": "10.0.0.0/35", "type": "cidr"}, headers=headers)
    assert res2.status_code == 400

    # Invalid Hash (not valid hex length)
    tgt_res = await async_client.post("/api/v1/targets", json={"value": "10.0.0.1"}, headers=headers)
    target_id = tgt_res.json()["id"]

    res3 = await async_client.post(
        f"/api/v1/targets/{target_id}/observables",
        json={"value": "not_a_valid_hash_value", "type": "sha256"},
        headers=headers,
    )
    assert res3.status_code == 400


# ==============================================================================
# 10. Duplicate Observable Handling
# ==============================================================================
@pytest.mark.asyncio
async def test_duplicate_observable_handling(async_client: AsyncClient, test_suffix: str):
    """Verifies duplicate observable in same organization is rejected with 409 Conflict."""
    headers, _ = await create_authenticated_user(async_client, test_suffix)

    tgt_res = await async_client.post("/api/v1/targets", json={"value": "10.240.1.1"}, headers=headers)
    target_id = tgt_res.json()["id"]

    obs_payload = {"value": "CVE-2024-38077", "type": "cve"}
    res1 = await async_client.post(f"/api/v1/targets/{target_id}/observables", json=obs_payload, headers=headers)
    assert res1.status_code == 201

    # Second attempt with same observable
    res2 = await async_client.post(f"/api/v1/targets/{target_id}/observables", json=obs_payload, headers=headers)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"].lower()


# ==============================================================================
# 11. Organization-Aware Deduplication
# ==============================================================================
@pytest.mark.asyncio
async def test_organization_aware_deduplication(async_client: AsyncClient, test_suffix: str):
    """Verifies that the same observable/target value can legitimately exist in different organizations."""
    headers_a, user_a = await create_authenticated_user(async_client, f"{test_suffix}-a", org_name="Org Alpha")
    headers_b, user_b = await create_authenticated_user(async_client, f"{test_suffix}-b", org_name="Org Bravo")

    shared_value = "185.220.101.5"

    # Org A creates target
    res_a = await async_client.post("/api/v1/targets", json={"value": shared_value, "label": "Org A Threat"}, headers=headers_a)
    assert res_a.status_code == 201

    # Org B creates same target value without collision
    res_b = await async_client.post("/api/v1/targets", json={"value": shared_value, "label": "Org B Threat"}, headers=headers_b)
    assert res_b.status_code == 201

    assert res_a.json()["organization_id"] == user_a["organization_id"]
    assert res_b.json()["organization_id"] == user_b["organization_id"]
    assert res_a.json()["id"] != res_b.json()["id"]


# ==============================================================================
# 12. Organization Isolation
# ==============================================================================
@pytest.mark.asyncio
async def test_organization_isolation(async_client: AsyncClient, test_suffix: str):
    """Verifies that Org A target list does not leak Org B targets."""
    headers_a, _ = await create_authenticated_user(async_client, f"{test_suffix}-a1", org_name="Tenant One")
    headers_b, _ = await create_authenticated_user(async_client, f"{test_suffix}-b1", org_name="Tenant Two")

    # Ingest target in Org A
    await async_client.post("/api/v1/targets", json={"value": "10.10.10.10", "label": "Secret Node Org A"}, headers=headers_a)

    # Ingest target in Org B
    await async_client.post("/api/v1/targets", json={"value": "10.20.20.20", "label": "Secret Node Org B"}, headers=headers_b)

    # Org A lists
    list_a = (await async_client.get("/api/v1/targets", headers=headers_a)).json()
    assert any(t["value"] == "10.10.10.10" for t in list_a["items"])
    assert not any(t["value"] == "10.20.20.20" for t in list_a["items"])

    # Org B lists
    list_b = (await async_client.get("/api/v1/targets", headers=headers_b)).json()
    assert any(t["value"] == "10.20.20.20" for t in list_b["items"])
    assert not any(t["value"] == "10.10.10.10" for t in list_b["items"])


# ==============================================================================
# 13. Cross-Organization Read Rejection
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_org_read_rejection(async_client: AsyncClient, test_suffix: str):
    """Verifies that attempting to read a target belonging to another organization returns 404."""
    headers_a, _ = await create_authenticated_user(async_client, f"{test_suffix}-a2", org_name="Tenant A")
    headers_b, _ = await create_authenticated_user(async_client, f"{test_suffix}-b2", org_name="Tenant B")

    # Org A creates target
    res_a = await async_client.post("/api/v1/targets", json={"value": "10.50.50.1", "label": "Org A Confidential"}, headers=headers_a)
    target_id = res_a.json()["id"]

    # Org B attempts to read Org A target
    read_attempt = await async_client.get(f"/api/v1/targets/{target_id}", headers=headers_b)
    assert read_attempt.status_code == 404
    assert "not found" in read_attempt.json()["detail"].lower()


# ==============================================================================
# 14. Cross-Organization Update Rejection
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_org_update_rejection(async_client: AsyncClient, test_suffix: str):
    """Verifies that attempting to modify a target belonging to another organization returns 404."""
    headers_a, _ = await create_authenticated_user(async_client, f"{test_suffix}-a3", org_name="Tenant A")
    headers_b, _ = await create_authenticated_user(async_client, f"{test_suffix}-b3", org_name="Tenant B")

    # Org A creates target
    res_a = await async_client.post("/api/v1/targets", json={"value": "10.60.60.1", "label": "Org A Node"}, headers=headers_a)
    target_id = res_a.json()["id"]

    # Org B attempts to update Org A target
    update_attempt = await async_client.patch(
        f"/api/v1/targets/{target_id}",
        json={"label": "Malicious Tampering Attempt"},
        headers=headers_b,
    )
    assert update_attempt.status_code == 404


# ==============================================================================
# 15. Cross-Organization Delete Rejection
# ==============================================================================
@pytest.mark.asyncio
async def test_cross_org_delete_rejection(async_client: AsyncClient, test_suffix: str):
    """Verifies that attempting to delete another organization's target returns 404."""
    headers_a, _ = await create_authenticated_user(async_client, f"{test_suffix}-a4", org_name="Tenant A")
    headers_b, _ = await create_authenticated_user(async_client, f"{test_suffix}-b4", org_name="Tenant B")

    # Org A creates target
    res_a = await async_client.post("/api/v1/targets", json={"value": "10.70.70.1", "label": "Protected Asset"}, headers=headers_a)
    target_id = res_a.json()["id"]

    # Org B attempts to delete Org A target
    del_attempt = await async_client.delete(f"/api/v1/targets/{target_id}", headers=headers_b)
    assert del_attempt.status_code == 404

    # Verify target still intact in Org A
    verify_res = await async_client.get(f"/api/v1/targets/{target_id}", headers=headers_a)
    assert verify_res.status_code == 200


# ==============================================================================
# 16. Unauthenticated Access Rejection
# ==============================================================================
@pytest.mark.asyncio
async def test_unauthenticated_access_rejection(async_client: AsyncClient):
    """Verifies that unauthenticated requests to target endpoints are rejected with 401."""
    res_list = await async_client.get("/api/v1/targets")
    assert res_list.status_code == 401

    res_create = await async_client.post("/api/v1/targets", json={"value": "1.1.1.1"})
    assert res_create.status_code == 401

    fake_id = str(uuid.uuid4())
    res_get = await async_client.get(f"/api/v1/targets/{fake_id}")
    assert res_get.status_code == 401

    res_del = await async_client.delete(f"/api/v1/targets/{fake_id}")
    assert res_del.status_code == 401


# ==============================================================================
# 17. RBAC Permission Enforcement
# ==============================================================================
@pytest.mark.asyncio
async def test_rbac_permission_enforcement(async_client: AsyncClient, test_suffix: str):
    """Verifies that users lacking required permissions are rejected with 403 Forbidden."""
    # Register analyst with standard account
    headers, user = await create_authenticated_user(async_client, test_suffix)

    # Manually create a user with a restricted role that lacks 'targets:delete'
    async with AsyncSessionLocal() as session:
        user_uuid = uuid.UUID(user["id"])
        org_uuid = uuid.UUID(user["organization_id"])

        # Create restricted role without targets:delete
        restricted_role = Role(
            organization_id=org_uuid,
            name=f"Read-Only Analyst {test_suffix}",
            description="Read-only access",
        )
        session.add(restricted_role)
        await session.flush()

        # Add only targets:read to this restricted role
        read_perm = (await session.execute(select(Permission).where(Permission.key == "targets:read"))).scalar_one()
        await session.execute(
            insert(role_permissions).values(role_id=restricted_role.id, permission_id=read_perm.id)
        )

        # Create restricted user
        restricted_user = User(
            organization_id=org_uuid,
            email=f"readonly-{test_suffix}@defense.corp",
            display_name="Readonly Operator",
            hashed_password="hashed_pwd_stub",
            clearance_level=ClearanceLevel.SECRET.value,
        )
        session.add(restricted_user)
        await session.flush()

        await session.execute(
            insert(user_roles).values(user_id=restricted_user.id, role_id=restricted_role.id)
        )
        await session.commit()

    # Create target using authorized analyst
    create_res = await async_client.post("/api/v1/targets", json={"value": "172.16.0.1"}, headers=headers)
    target_id = create_res.json()["id"]

    # Generate token for restricted user
    from app.security.jwt import create_access_token
    restricted_token = create_access_token(
        data={"sub": str(restricted_user.id), "org": str(org_uuid)},
    )
    restricted_headers = {"Authorization": f"Bearer {restricted_token}"}

    # Restricted user CAN read targets
    read_res = await async_client.get(f"/api/v1/targets/{target_id}", headers=restricted_headers)
    assert read_res.status_code == 200

    # Restricted user CANNOT create targets (missing targets:create)
    create_attempt = await async_client.post("/api/v1/targets", json={"value": "172.16.0.2"}, headers=restricted_headers)
    assert create_attempt.status_code == 403
    assert "targets:create" in create_attempt.json()["detail"]

    # Restricted user CANNOT delete target (missing targets:delete)
    del_attempt = await async_client.delete(f"/api/v1/targets/{target_id}", headers=restricted_headers)
    assert del_attempt.status_code == 403
    assert "targets:delete" in del_attempt.json()["detail"]


# ==============================================================================
# 18. Audit Event Generation
# ==============================================================================
@pytest.mark.asyncio
async def test_audit_event_generation(async_client: AsyncClient, test_suffix: str):
    """Verifies that target lifecycle actions produce immutable audit logs without leaking secrets."""
    headers, user = await create_authenticated_user(async_client, test_suffix)

    # 1. Create target
    create_res = await async_client.post(
        "/api/v1/targets",
        json={"value": "10.88.88.1", "label": "Audit Test Target"},
        headers=headers,
    )
    assert create_res.status_code == 201
    target_id = create_res.json()["id"]

    # 2. Update target
    await async_client.patch(
        f"/api/v1/targets/{target_id}",
        json={"priority": "critical"},
        headers=headers,
    )

    # 3. Delete target
    await async_client.delete(f"/api/v1/targets/{target_id}", headers=headers)

    # Inspect audit_logs table
    async with AsyncSessionLocal() as session:
        org_uuid = uuid.UUID(user["organization_id"])
        stmt = (
            select(AuditLog)
            .where(AuditLog.organization_id == org_uuid)
            .order_by(AuditLog.created_at.desc())
        )
        logs = (await session.execute(stmt)).scalars().all()
        actions = [log.action for log in logs]

        assert "TARGET_CREATED" in actions
        assert "TARGET_UPDATED" in actions
        assert "TARGET_DELETED" in actions

        # Check safety: no password or auth cookie in details
        for log in logs:
            detail_str = str(log.details).lower()
            assert "password" not in detail_str or "[redacted]" in detail_str
            assert "access_token" not in detail_str or "[redacted]" in detail_str
            assert "refresh_token" not in detail_str or "[redacted]" in detail_str


# ==============================================================================
# 19. Migration Upgrade Verification
# ==============================================================================
def test_migration_upgrade():
    """Verifies that alembic upgrade head executes cleanly against PostgreSQL."""
    backend_dir = Path(__file__).resolve().parent.parent
    import sys

    upgrade_res = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert upgrade_res.returncode == 0, f"Upgrade failed: {upgrade_res.stderr}"

    current_res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert current_res.returncode == 0
    assert "(head)" in current_res.stdout


# ==============================================================================
# 20. Migration Downgrade & Re-upgrade Verification
# ==============================================================================
def test_migration_downgrade_and_reupgrade():
    """Verifies that migration downgrades cleanly and re-applies head without errors."""
    backend_dir = Path(__file__).resolve().parent.parent
    import sys

    # Downgrade 1 revision (reverts e5a8f23b9c10)
    downgrade_res = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "-1"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert downgrade_res.returncode == 0, f"Downgrade failed: {downgrade_res.stderr}"

    # Re-upgrade to head
    reupgrade_res = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert reupgrade_res.returncode == 0, f"Re-upgrade failed: {reupgrade_res.stderr}"

    # Verify head
    current_res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert current_res.returncode == 0
    assert "(head)" in current_res.stdout
