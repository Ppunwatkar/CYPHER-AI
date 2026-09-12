"""
CIPHER AI - Identity & Access Data Model Tests
Verifies SQLAlchemy models, constraints, relationships, organization isolation,
and Alembic migration lifecycle against PostgreSQL.
"""

import uuid
import pytest
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from app.models import (
    ClearanceLevel,
    Organization,
    OrganizationStatus,
    Permission,
    Role,
    TLPClassification,
    User,
    UserStatus,
    role_permissions,
    user_roles,
)


@pytest.fixture
def unique_suffix() -> str:
    """Generates a short random suffix for collision-free test entity attributes."""
    return uuid.uuid4().hex[:8]


@pytest.mark.asyncio
async def test_model_creation_and_defaults(unique_suffix: str):
    """Verifies creation of Organization, User, Role, Permission with UUIDs and defaults."""
    async with AsyncSessionLocal() as session:
        # 1. Organization
        org = Organization(
            name=f"Defense Cyber Operations {unique_suffix}",
            slug=f"defense-soc-{unique_suffix}",
        )
        session.add(org)
        await session.flush()

        assert isinstance(org.id, uuid.UUID)
        assert org.status == OrganizationStatus.ACTIVE.value
        assert org.is_active is True
        assert org.created_at is not None
        assert org.updated_at is not None

        # 2. Permission
        perm = Permission(
            key=f"intel:read:{unique_suffix}",
            name="Read Threat Intelligence",
            description="Allows read access to threat intel feeds",
        )
        session.add(perm)
        await session.flush()

        assert isinstance(perm.id, uuid.UUID)
        assert perm.created_at is not None

        # 3. Role
        role = Role(
            organization_id=org.id,
            name=f"SecOps Analyst {unique_suffix}",
            description="L1/L2 Security Operations Analyst",
        )
        session.add(role)
        await session.flush()

        assert isinstance(role.id, uuid.UUID)
        assert role.organization_id == org.id
        assert role.created_at is not None
        assert role.updated_at is not None

        # 4. User
        user = User(
            organization_id=org.id,
            email=f"analyst-{unique_suffix}@defense.corp",
            display_name="Senior Analyst",
            clearance_level=ClearanceLevel.SECRET.value,
        )
        session.add(user)
        await session.flush()

        assert isinstance(user.id, uuid.UUID)
        assert user.organization_id == org.id
        assert user.status == UserStatus.ACTIVE.value
        assert user.is_active is True
        assert user.clearance_level == ClearanceLevel.SECRET.value
        assert user.clearance == ClearanceLevel.SECRET
        assert user.created_at is not None
        assert user.updated_at is not None

        # Repr safety: should not crash and not leak secrets
        repr_str = repr(user)
        assert "User" in repr_str
        assert "password" not in repr_str.lower()

        # Clean up
        await session.delete(org)
        await session.delete(perm)
        await session.commit()


@pytest.mark.asyncio
async def test_foreign_key_relationships_and_cascade(unique_suffix: str):
    """Verifies foreign-key integrity and cascade deletion from Organization to Users/Roles."""
    async with AsyncSessionLocal() as session:
        # Create Organization with User and Role
        org = Organization(
            name=f"Air Force SOC {unique_suffix}",
            slug=f"air-force-soc-{unique_suffix}",
        )
        session.add(org)
        await session.flush()

        role = Role(
            organization_id=org.id,
            name=f"Hunter-{unique_suffix}",
            description="Threat Hunter",
        )
        user = User(
            organization_id=org.id,
            email=f"hunter-{unique_suffix}@mil.defense",
            display_name="Threat Hunter Alpha",
        )
        session.add_all([role, user])
        await session.commit()

        org_id = org.id
        user_id = user.id
        role_id = role.id

    # Verify foreign key resolution in fresh session
    async with AsyncSessionLocal() as session:
        res_user = await session.get(User, user_id)
        assert res_user is not None
        assert res_user.organization_id == org_id

        res_role = await session.get(Role, role_id)
        assert res_role is not None
        assert res_role.organization_id == org_id

        # Delete Organization and verify cascade deletion
        res_org = await session.get(Organization, org_id)
        await session.delete(res_org)
        await session.commit()

    # Confirm associated user and role are deleted by database cascade
    async with AsyncSessionLocal() as session:
        cascaded_user = await session.get(User, user_id)
        cascaded_role = await session.get(Role, role_id)
        assert cascaded_user is None
        assert cascaded_role is None


@pytest.mark.asyncio
async def test_unique_constraints(unique_suffix: str):
    """Verifies unique constraints on organization slug, user email, permission key, and (org_id, role_name)."""
    async with AsyncSessionLocal() as session:
        org = Organization(
            name=f"Cyber Command {unique_suffix}",
            slug=f"cyber-cmd-{unique_suffix}",
        )
        session.add(org)
        await session.commit()
        org_id = org.id

    # 1. Duplicate Organization Slug
    async with AsyncSessionLocal() as session:
        dup_org = Organization(
            name=f"Duplicate Command {unique_suffix}",
            slug=f"cyber-cmd-{unique_suffix}",  # Duplicate
        )
        session.add(dup_org)
        with pytest.raises(IntegrityError):
            await session.commit()

    # 2. Duplicate User Email
    async with AsyncSessionLocal() as session:
        user1 = User(
            organization_id=org_id,
            email=f"operator-{unique_suffix}@cyber.mil",
            display_name="Operator 1",
        )
        session.add(user1)
        await session.commit()

    async with AsyncSessionLocal() as session:
        user2 = User(
            organization_id=org_id,
            email=f"operator-{unique_suffix}@cyber.mil",  # Duplicate email
            display_name="Operator 2",
        )
        session.add(user2)
        with pytest.raises(IntegrityError):
            await session.commit()

    # 3. Duplicate Permission Key
    async with AsyncSessionLocal() as session:
        perm1 = Permission(
            key=f"target:scan:{unique_suffix}",
            name="Scan Target",
        )
        session.add(perm1)
        await session.commit()

    async with AsyncSessionLocal() as session:
        perm2 = Permission(
            key=f"target:scan:{unique_suffix}",  # Duplicate key
            name="Scan Target Duplicate",
        )
        session.add(perm2)
        with pytest.raises(IntegrityError):
            await session.commit()

    # 4. Duplicate Role Name in Same Organization
    async with AsyncSessionLocal() as session:
        role1 = Role(
            organization_id=org_id,
            name=f"Auditor-{unique_suffix}",
        )
        session.add(role1)
        await session.commit()

    async with AsyncSessionLocal() as session:
        role2 = Role(
            organization_id=org_id,
            name=f"Auditor-{unique_suffix}",  # Duplicate role in same org
        )
        session.add(role2)
        with pytest.raises(IntegrityError):
            await session.commit()

    # Cleanup
    async with AsyncSessionLocal() as session:
        res_org = await session.get(Organization, org_id)
        if res_org:
            await session.delete(res_org)
        perm = (await session.execute(select(Permission).where(Permission.key == f"target:scan:{unique_suffix}"))).scalar_one_or_none()
        if perm:
            await session.delete(perm)
        await session.commit()


@pytest.mark.asyncio
async def test_organization_isolation(unique_suffix: str):
    """
    Verifies multi-tenant isolation:
    Queries scoped by organization_id strictly partition users and roles,
    preventing cross-tenant data leakage.
    """
    async with AsyncSessionLocal() as session:
        # Create Organization A
        org_a = Organization(
            name=f"Tenant A {unique_suffix}",
            slug=f"tenant-a-{unique_suffix}",
        )
        # Create Organization B
        org_b = Organization(
            name=f"Tenant B {unique_suffix}",
            slug=f"tenant-b-{unique_suffix}",
        )
        session.add_all([org_a, org_b])
        await session.flush()

        # Add users to Org A
        user_a1 = User(
            organization_id=org_a.id,
            email=f"a1-{unique_suffix}@tenant-a.com",
            display_name="User A1",
        )
        user_a2 = User(
            organization_id=org_a.id,
            email=f"a2-{unique_suffix}@tenant-a.com",
            display_name="User A2",
        )

        # Add users to Org B
        user_b1 = User(
            organization_id=org_b.id,
            email=f"b1-{unique_suffix}@tenant-b.com",
            display_name="User B1",
        )
        user_b2 = User(
            organization_id=org_b.id,
            email=f"b2-{unique_suffix}@tenant-b.com",
            display_name="User B2",
        )

        session.add_all([user_a1, user_a2, user_b1, user_b2])
        await session.commit()

        org_a_id = org_a.id
        org_b_id = org_b.id

    # Query scoped to Org A
    async with AsyncSessionLocal() as session:
        stmt_a = select(User).where(User.organization_id == org_a_id)
        users_a = (await session.execute(stmt_a)).scalars().all()

        assert len(users_a) == 2
        user_a_emails = {u.email for u in users_a}
        assert f"a1-{unique_suffix}@tenant-a.com" in user_a_emails
        assert f"a2-{unique_suffix}@tenant-a.com" in user_a_emails
        # Ensure zero leakage from Org B
        assert not any(u.email.startswith(f"b1-{unique_suffix}") for u in users_a)
        assert not any(u.email.startswith(f"b2-{unique_suffix}") for u in users_a)

    # Query scoped to Org B
    async with AsyncSessionLocal() as session:
        stmt_b = select(User).where(User.organization_id == org_b_id)
        users_b = (await session.execute(stmt_b)).scalars().all()

        assert len(users_b) == 2
        user_b_emails = {u.email for u in users_b}
        assert f"b1-{unique_suffix}@tenant-b.com" in user_b_emails
        assert f"b2-{unique_suffix}@tenant-b.com" in user_b_emails
        # Ensure zero leakage from Org A
        assert not any(u.email.startswith(f"a1-{unique_suffix}") for u in users_b)
        assert not any(u.email.startswith(f"a2-{unique_suffix}") for u in users_b)

    # Cleanup Org A only; verify Org B is unaffected
    async with AsyncSessionLocal() as session:
        res_a = await session.get(Organization, org_a_id)
        await session.delete(res_a)
        await session.commit()

    async with AsyncSessionLocal() as session:
        # Org B users still exist
        stmt_b = select(User).where(User.organization_id == org_b_id)
        remaining_b = (await session.execute(stmt_b)).scalars().all()
        assert len(remaining_b) == 2

        # Org A users are completely gone
        stmt_a = select(User).where(User.organization_id == org_a_id)
        remaining_a = (await session.execute(stmt_a)).scalars().all()
        assert len(remaining_a) == 0

        # Clean up Org B
        res_b = await session.get(Organization, org_b_id)
        await session.delete(res_b)
        await session.commit()


@pytest.mark.asyncio
async def test_role_permission_and_user_role_relationships(unique_suffix: str):
    """Verifies many-to-many associations: Role <-> Permission and User <-> Role."""
    async with AsyncSessionLocal() as session:
        org = Organization(
            name=f"SOC Red Team {unique_suffix}",
            slug=f"soc-red-{unique_suffix}",
        )
        session.add(org)
        await session.flush()

        # Create permissions
        perm_recon = Permission(
            key=f"recon:execute:{unique_suffix}",
            name="Execute Network Recon",
        )
        perm_exploit = Permission(
            key=f"exploit:test:{unique_suffix}",
            name="Test Exploit Resilience",
        )
        perm_report = Permission(
            key=f"report:generate:{unique_suffix}",
            name="Generate Findings Report",
        )
        session.add_all([perm_recon, perm_exploit, perm_report])
        await session.flush()

        # Create role with recon and report permissions
        role_red = Role(
            organization_id=org.id,
            name=f"Red Team Specialist {unique_suffix}",
            permissions=[perm_recon, perm_report],
        )
        session.add(role_red)
        await session.flush()

        # Verify role permission check
        assert role_red.has_permission(f"recon:execute:{unique_suffix}") is True
        assert role_red.has_permission(f"report:generate:{unique_suffix}") is True
        assert role_red.has_permission(f"exploit:test:{unique_suffix}") is False

        # Create user with role
        user = User(
            organization_id=org.id,
            email=f"red-lead-{unique_suffix}@defense.gov",
            display_name="Red Team Lead",
            roles=[role_red],
        )
        session.add(user)
        await session.commit()

        user_id = user.id
        role_id = role_red.id

    # Verify relationships in fresh session
    async with AsyncSessionLocal() as session:
        loaded_user = await session.get(User, user_id)
        assert loaded_user is not None
        assert len(loaded_user.roles) == 1
        assert loaded_user.has_role(f"Red Team Specialist {unique_suffix}") is True
        assert loaded_user.has_role("Unknown Role") is False
        assert loaded_user.has_permission(f"recon:execute:{unique_suffix}") is True
        assert loaded_user.has_permission(f"report:generate:{unique_suffix}") is True
        assert loaded_user.has_permission(f"exploit:test:{unique_suffix}") is False

        # Disassociate role from user
        loaded_user.roles.clear()
        await session.commit()

    # Confirm user has no roles, but role and permissions still exist
    async with AsyncSessionLocal() as session:
        user_after = await session.get(User, user_id)
        assert len(user_after.roles) == 0
        assert user_after.has_permission(f"recon:execute:{unique_suffix}") is False

        role_after = await session.get(Role, role_id)
        assert role_after is not None
        assert len(role_after.permissions) == 2

        # Clean up
        org_to_del = await session.get(Organization, org.id)
        if org_to_del:
            await session.delete(org_to_del)
        await session.execute(
            delete(Permission).where(
                Permission.key.in_([
                    f"recon:execute:{unique_suffix}",
                    f"exploit:test:{unique_suffix}",
                    f"report:generate:{unique_suffix}",
                ])
            )
        )
        await session.commit()


def test_clearance_and_tlp_separation():
    """
    CRITICAL SECURITY SPECIFICATION TEST:
    Verifies that Security Clearance (ClearanceLevel) and TLP (TLPClassification)
    are strictly distinct and cannot be conflated.
    """
    # 1. Clearance Level Hierarchy
    assert ClearanceLevel.UNCLASSIFIED.level_rank < ClearanceLevel.RESTRICTED.level_rank
    assert ClearanceLevel.RESTRICTED.level_rank < ClearanceLevel.CONFIDENTIAL.level_rank
    assert ClearanceLevel.CONFIDENTIAL.level_rank < ClearanceLevel.SECRET.level_rank
    assert ClearanceLevel.SECRET.level_rank < ClearanceLevel.TOP_SECRET.level_rank

    # Clearance satisfaction
    secret = ClearanceLevel.SECRET
    assert secret.satisfies(ClearanceLevel.UNCLASSIFIED) is True
    assert secret.satisfies(ClearanceLevel.RESTRICTED) is True
    assert secret.satisfies(ClearanceLevel.CONFIDENTIAL) is True
    assert secret.satisfies(ClearanceLevel.SECRET) is True
    assert secret.satisfies(ClearanceLevel.TOP_SECRET) is False

    # 2. TLP Classification is separate from Clearance
    # TLP values are standardized data-sharing strings
    assert TLPClassification.CLEAR.value == "TLP:CLEAR"
    assert TLPClassification.GREEN.value == "TLP:GREEN"
    assert TLPClassification.AMBER.value == "TLP:AMBER"
    assert TLPClassification.AMBER_STRICT.value == "TLP:AMBER+STRICT"
    assert TLPClassification.RED.value == "TLP:RED"

    # Ensure TLP does NOT have clearance ranks
    assert not hasattr(TLPClassification.RED, "level_rank")
    assert not hasattr(TLPClassification.AMBER, "satisfies")

    # Enums are distinct types
    assert type(ClearanceLevel.SECRET) is not type(TLPClassification.RED)
    assert ClearanceLevel.SECRET != TLPClassification.RED


@pytest.mark.asyncio
async def test_migration_lifecycle_programmatic():
    """
    Verifies that Alembic migration upgrade and downgrade work seamlessly
    and idempotently against the live PostgreSQL database.
    """
    import subprocess
    from pathlib import Path

    backend_dir = Path(__file__).resolve().parent.parent
    import sys

    # 1. Test Downgrade to base
    downgrade_res = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "base"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert downgrade_res.returncode == 0, f"Downgrade failed: {downgrade_res.stderr}"

    # 2. Test Upgrade back to head
    upgrade_res = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert upgrade_res.returncode == 0, f"Upgrade failed: {upgrade_res.stderr}"

    # 3. Verify current revision is at head
    current_res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
    )
    assert current_res.returncode == 0
    assert "(head)" in current_res.stdout

