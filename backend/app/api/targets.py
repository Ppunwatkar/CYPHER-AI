"""
CIPHER AI - Security Target & Observable REST API
Provides full CRUD, authoritative normalization, tenant-isolated operations, and RBAC governance.
"""

from datetime import datetime, timezone
import logging
from typing import List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import log_audit_event
from app.database.session import get_db
from app.models import Observable, SecurityTarget, User
from app.schemas.target import (
    ObservableCreateRequest,
    ObservableListResponse,
    ObservableResponse,
    TargetBulkCreateRequest,
    TargetBulkCreateResponse,
    TargetCreateRequest,
    TargetListResponse,
    TargetResponse,
    TargetUpdateRequest,
)
from app.security.deps import get_current_active_user, require_permission
from app.services.normalization import normalize_indicator

logger = logging.getLogger("cipher.api.targets")

router = APIRouter(prefix="/targets", tags=["Security Targets & Observables"])


def _format_target(target: SecurityTarget) -> TargetResponse:
    """Formats a SecurityTarget model instance into the validated TargetResponse DTO."""
    owner_name = target.creator.display_name if target.creator else "SecOps Analyst"
    created_iso = target.created_at.isoformat() if target.created_at else datetime.now(timezone.utc).isoformat()
    scanned_iso = target.last_scanned_at.isoformat() if target.last_scanned_at else None

    return TargetResponse(
        id=str(target.id),
        organization_id=str(target.organization_id),
        name=target.name,
        label=target.name,
        target_type=target.target_type,
        type=target.target_type,
        normalized_value=target.normalized_value,
        value=target.normalized_value,
        original_value=target.original_value,
        status=target.status,
        environment=target.environment,
        priority=target.priority,
        threat_score=target.threat_score,
        threatScore=target.threat_score,
        verdict=target.verdict,
        risk_level=target.risk_level,
        riskLevel=target.risk_level,
        confidence=target.confidence,
        asn=target.asn,
        country=target.country,
        city=target.city,
        open_ports=target.open_ports or [],
        openPorts=target.open_ports or [],
        tags=target.tags or [],
        notes=target.notes,
        description=target.description,
        owner=owner_name,
        created_at=target.created_at or datetime.now(timezone.utc),
        addedAt=created_iso,
        updated_at=target.updated_at or datetime.now(timezone.utc),
        last_scanned_at=target.last_scanned_at,
        lastScannedAt=scanned_iso,
    )


def _format_observable(obs: Observable) -> ObservableResponse:
    """Formats an Observable model instance into the ObservableResponse DTO."""
    return ObservableResponse(
        id=str(obs.id),
        organization_id=str(obs.organization_id),
        target_id=str(obs.target_id) if obs.target_id else None,
        observable_type=obs.observable_type,
        type=obs.observable_type,
        normalized_value=obs.normalized_value,
        value=obs.normalized_value,
        original_value=obs.original_value,
        source=obs.source,
        confidence=obs.confidence,
        severity=obs.severity,
        status=obs.status,
        first_seen=obs.first_seen,
        last_seen=obs.last_seen,
        created_at=obs.created_at,
        updated_at=obs.updated_at,
    )


# ==============================================================================
# 1. Target CRUD Operations
# ==============================================================================

@router.get(
    "",
    response_model=TargetListResponse,
    summary="List Organization Security Targets",
    description="Retrieves security targets belonging exclusively to the authenticated user's organization.",
)
async def list_targets(
    search: Optional[str] = Query(None, description="Search term across value, label, ASN, or tags"),
    type: Optional[str] = Query(None, description="Filter by target type (ipv4, domain, cidr, etc.)"),
    environment: Optional[str] = Query(None, description="Filter by environment (production, external_threat, etc.)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (QUEUED, ANALYZING, etc.)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("targets:read")),
    db: AsyncSession = Depends(get_db),
) -> TargetListResponse:
    """Lists organization targets with optional filtering and pagination."""
    query = (
        select(SecurityTarget)
        .options(selectinload(SecurityTarget.creator))
        .where(SecurityTarget.organization_id == current_user.organization_id)
    )

    # Filter by type
    if type and type != "all":
        query = query.where(SecurityTarget.target_type == type.lower())

    # Filter by environment
    if environment and environment != "all":
        query = query.where(SecurityTarget.environment == environment.lower())

    # Filter by status
    if status_filter and status_filter != "all":
        query = query.where(SecurityTarget.status == status_filter.upper())

    # Text search
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                SecurityTarget.normalized_value.ilike(term),
                SecurityTarget.name.ilike(term),
                SecurityTarget.asn.ilike(term),
                SecurityTarget.notes.ilike(term),
            )
        )

    # Total count
    count_stmt = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # Ordered pagination
    query = query.order_by(SecurityTarget.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    targets = result.scalars().all()

    return TargetListResponse(
        items=[_format_target(t) for t in targets],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Security Target",
    description="Validates and normalizes target value before persisting within the authenticated organization.",
)
async def create_target(
    req: TargetCreateRequest,
    request: Request,
    current_user: User = Depends(require_permission("targets:create")),
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """Creates a new normalized security target bounded by organization."""
    # 1. Authoritative Backend Normalization & Validation
    norm_res = normalize_indicator(req.value, req.type)
    if not norm_res.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {norm_res.error_message}",
        )

    # 2. Organization-aware deduplication check
    existing_stmt = select(SecurityTarget).where(
        (SecurityTarget.organization_id == current_user.organization_id)
        & (SecurityTarget.target_type == norm_res.detected_type)
        & (SecurityTarget.normalized_value == norm_res.normalized_value)
    )
    existing_target = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing_target:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target '{norm_res.normalized_value}' of type '{norm_res.detected_type}' already exists in your organization.",
        )

    label = req.label.strip() if req.label else norm_res.normalized_value
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    # 3. Instantiate Entity
    target = SecurityTarget(
        organization_id=current_user.organization_id,
        name=label,
        target_type=norm_res.detected_type,
        normalized_value=norm_res.normalized_value,
        original_value=req.value,
        status=req.status or "QUEUED",
        environment=req.environment or "external_threat",
        priority=req.priority or "high",
        threat_score=req.threat_score or 0,
        verdict=req.verdict or "unknown",
        risk_level=req.risk_level or "UNKNOWN",
        confidence=req.confidence or 0,
        asn=req.asn,
        country=req.country,
        city=req.city,
        open_ports=req.open_ports or [],
        tags=req.tags or [],
        notes=req.notes,
        description=req.description,
        created_by=current_user.id,
    )
    db.add(target)
    await db.flush()

    # 4. Audit Log Event
    await log_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        action="TARGET_CREATED",
        resource_type="security_target",
        actor=current_user,
        resource_id=str(target.id),
        details={
            "value": target.normalized_value,
            "type": target.target_type,
            "environment": target.environment,
            "priority": target.priority,
        },
        request_id=request_id,
        ip_address=client_ip,
    )

    await db.commit()
    await db.refresh(target, ["creator"])

    return _format_target(target)


@router.post(
    "/bulk",
    response_model=TargetBulkCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk Ingest Security Targets",
    description="Ingests multiple targets with backend normalization and duplicate handling.",
)
async def bulk_create_targets(
    req: TargetBulkCreateRequest,
    request: Request,
    current_user: User = Depends(require_permission("targets:create")),
    db: AsyncSession = Depends(get_db),
) -> TargetBulkCreateResponse:
    """Bulk ingestion endpoint for Target Inventory."""
    created_items: List[TargetResponse] = []
    skipped = 0
    errors: List[dict] = []
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    for item in req.targets:
        norm_res = normalize_indicator(item.value, item.type)
        if not norm_res.is_valid:
            errors.append({"value": item.value, "error": norm_res.error_message})
            continue

        existing_stmt = select(SecurityTarget).where(
            (SecurityTarget.organization_id == current_user.organization_id)
            & (SecurityTarget.target_type == norm_res.detected_type)
            & (SecurityTarget.normalized_value == norm_res.normalized_value)
        )
        if (await db.execute(existing_stmt)).scalar_one_or_none():
            skipped += 1
            continue

        label = item.label.strip() if item.label else norm_res.normalized_value
        target = SecurityTarget(
            organization_id=current_user.organization_id,
            name=label,
            target_type=norm_res.detected_type,
            normalized_value=norm_res.normalized_value,
            original_value=item.value,
            status=item.status or "QUEUED",
            environment=item.environment or "external_threat",
            priority=item.priority or "high",
            threat_score=item.threat_score or 0,
            verdict=item.verdict or "unknown",
            risk_level=item.risk_level or "UNKNOWN",
            confidence=item.confidence or 0,
            asn=item.asn,
            country=item.country,
            city=item.city,
            open_ports=item.open_ports or [],
            tags=item.tags or [],
            notes=item.notes,
            description=item.description,
            created_by=current_user.id,
        )
        db.add(target)
        await db.flush()
        await db.refresh(target, ["creator"])
        created_items.append(_format_target(target))

    if created_items:
        await log_audit_event(
            db=db,
            organization_id=current_user.organization_id,
            action="TARGETS_BULK_INGESTED",
            resource_type="security_target",
            actor=current_user,
            details={"count": len(created_items), "skipped": skipped},
            request_id=request_id,
            ip_address=client_ip,
        )

    await db.commit()

    return TargetBulkCreateResponse(
        created_count=len(created_items),
        skipped_count=skipped,
        items=created_items,
        errors=errors,
    )


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Retrieve Target by ID",
    description="Retrieves a single security target. Guarantees strict cross-organization access rejection.",
)
async def get_target(
    target_id: uuid.UUID,
    current_user: User = Depends(require_permission("targets:read")),
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """Fetches a target verifying organization ownership."""
    stmt = (
        select(SecurityTarget)
        .options(selectinload(SecurityTarget.creator))
        .where(
            (SecurityTarget.id == target_id)
            & (SecurityTarget.organization_id == current_user.organization_id)
        )
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security target not found.",
        )
    return _format_target(target)


@router.patch(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Update Security Target",
    description="Partially modifies security target metadata. Rejects cross-tenant updates.",
)
async def update_target(
    target_id: uuid.UUID,
    req: TargetUpdateRequest,
    request: Request,
    current_user: User = Depends(require_permission("targets:update")),
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """Updates target fields within the user's organization."""
    stmt = (
        select(SecurityTarget)
        .options(selectinload(SecurityTarget.creator))
        .where(
            (SecurityTarget.id == target_id)
            & (SecurityTarget.organization_id == current_user.organization_id)
        )
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security target not found.",
        )

    # Apply partial updates
    if req.label is not None:
        target.name = req.label.strip()
    if req.environment is not None:
        target.environment = req.environment.lower()
    if req.priority is not None:
        target.priority = req.priority.lower()
    if req.status is not None:
        target.status = req.status.upper()
    if req.threat_score is not None:
        target.threat_score = req.threat_score
    if req.verdict is not None:
        target.verdict = req.verdict.lower()
    if req.risk_level is not None:
        target.risk_level = req.risk_level.upper()
    if req.confidence is not None:
        target.confidence = req.confidence
    if req.asn is not None:
        target.asn = req.asn
    if req.country is not None:
        target.country = req.country
    if req.city is not None:
        target.city = req.city
    if req.open_ports is not None:
        target.open_ports = req.open_ports
    if req.tags is not None:
        target.tags = req.tags
    if req.notes is not None:
        target.notes = req.notes
    if req.description is not None:
        target.description = req.description

    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    await log_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        action="TARGET_UPDATED",
        resource_type="security_target",
        actor=current_user,
        resource_id=str(target.id),
        details={"updated_fields": list(req.model_dump(exclude_unset=True).keys())},
        request_id=request_id,
        ip_address=client_ip,
    )

    await db.commit()
    await db.refresh(target, ["creator"])
    return _format_target(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Security Target",
    description="Removes a target and cascades to child observables. Enforces tenant boundary.",
)
async def delete_target(
    target_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission("targets:delete")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Deletes a target and its associated observables within the organization."""
    stmt = select(SecurityTarget).where(
        (SecurityTarget.id == target_id)
        & (SecurityTarget.organization_id == current_user.organization_id)
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security target not found.",
        )

    target_val = target.normalized_value
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    await db.delete(target)

    await log_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        action="TARGET_DELETED",
        resource_type="security_target",
        actor=current_user,
        resource_id=str(target_id),
        details={"value": target_val},
        request_id=request_id,
        ip_address=client_ip,
    )

    await db.commit()
    return {"success": True, "message": f"Target {target_val} deleted successfully."}


# ==============================================================================
# 2. Observable Endpoints Scoped to Target
# ==============================================================================

@router.get(
    "/{target_id}/observables",
    response_model=ObservableListResponse,
    summary="List Target Observables",
    description="Lists all technical observables associated with a specific security target.",
)
async def list_target_observables(
    target_id: uuid.UUID,
    current_user: User = Depends(require_permission("targets:read")),
    db: AsyncSession = Depends(get_db),
) -> ObservableListResponse:
    """Lists observables attached to a target."""
    # Ensure target exists and belongs to user's org
    tgt_stmt = select(SecurityTarget.id).where(
        (SecurityTarget.id == target_id)
        & (SecurityTarget.organization_id == current_user.organization_id)
    )
    if not (await db.execute(tgt_stmt)).scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security target not found.",
        )

    obs_stmt = (
        select(Observable)
        .where(
            (Observable.target_id == target_id)
            & (Observable.organization_id == current_user.organization_id)
        )
        .order_by(Observable.created_at.desc())
    )
    observables = (await db.execute(obs_stmt)).scalars().all()
    return ObservableListResponse(
        items=[_format_observable(o) for o in observables],
        total=len(observables),
    )


@router.post(
    "/{target_id}/observables",
    response_model=ObservableResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Target Observable",
    description="Normalizes and persists an observable linked to a target.",
)
async def create_target_observable(
    target_id: uuid.UUID,
    req: ObservableCreateRequest,
    request: Request,
    current_user: User = Depends(require_permission("targets:create")),
    db: AsyncSession = Depends(get_db),
) -> ObservableResponse:
    """Attaches a new normalized observable to a target."""
    # 1. Validate parent target ownership
    tgt_stmt = select(SecurityTarget).where(
        (SecurityTarget.id == target_id)
        & (SecurityTarget.organization_id == current_user.organization_id)
    )
    target = (await db.execute(tgt_stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security target not found.",
        )

    # 2. Authoritative Normalization
    norm_res = normalize_indicator(req.value, req.type)
    if not norm_res.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Observable validation failed: {norm_res.error_message}",
        )

    # 3. Check for duplicates within organization
    existing_stmt = select(Observable).where(
        (Observable.organization_id == current_user.organization_id)
        & (Observable.observable_type == norm_res.detected_type)
        & (Observable.normalized_value == norm_res.normalized_value)
    )
    existing_obs = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing_obs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Observable '{norm_res.normalized_value}' ({norm_res.detected_type}) already exists in your organization.",
        )

    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    obs = Observable(
        organization_id=current_user.organization_id,
        target_id=target_id,
        observable_type=norm_res.detected_type,
        normalized_value=norm_res.normalized_value,
        original_value=req.value,
        source=req.source or "manual",
        confidence=req.confidence or 80,
        severity=req.severity or "high",
        status=req.status or "active",
    )
    db.add(obs)
    await db.flush()

    await log_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        action="OBSERVABLE_CREATED",
        resource_type="observable",
        actor=current_user,
        resource_id=str(obs.id),
        details={
            "value": obs.normalized_value,
            "type": obs.observable_type,
            "target_id": str(target_id),
        },
        request_id=request_id,
        ip_address=client_ip,
    )

    await db.commit()
    await db.refresh(obs)
    return _format_observable(obs)


@router.delete(
    "/{target_id}/observables/{observable_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Target Observable",
    description="Deletes an observable linked to a target. Enforces tenant boundary.",
)
async def delete_target_observable(
    target_id: uuid.UUID,
    observable_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission("targets:delete")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Deletes an observable associated with a target."""
    stmt = select(Observable).where(
        (Observable.id == observable_id)
        & (Observable.target_id == target_id)
        & (Observable.organization_id == current_user.organization_id)
    )
    obs = (await db.execute(stmt)).scalar_one_or_none()
    if not obs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Observable not found for this target.",
        )

    obs_val = obs.normalized_value
    request_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    await db.delete(obs)

    await log_audit_event(
        db=db,
        organization_id=current_user.organization_id,
        action="OBSERVABLE_DELETED",
        resource_type="observable",
        actor=current_user,
        resource_id=str(observable_id),
        details={"value": obs_val, "target_id": str(target_id)},
        request_id=request_id,
        ip_address=client_ip,
    )

    await db.commit()
    return {"success": True, "message": f"Observable {obs_val} deleted successfully."}


# ==============================================================================
# 3. Organization-Wide Observable Search
# ==============================================================================

@router.get(
    "/observables/search",
    response_model=ObservableListResponse,
    summary="Search Organization Observables",
    description="Safe search for observables across the organization without executing indicators.",
)
async def search_observables(
    query: str = Query(..., min_length=1, description="Search query string"),
    type: Optional[str] = Query(None, description="Optional observable type filter"),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(require_permission("targets:read")),
    db: AsyncSession = Depends(get_db),
) -> ObservableListResponse:
    """Searches organization observables safely."""
    clean_query = query.strip()
    stmt = select(Observable).where(Observable.organization_id == current_user.organization_id)

    if type and type != "all":
        stmt = stmt.where(Observable.observable_type == type.lower())

    term = f"%{clean_query}%"
    stmt = stmt.where(
        or_(
            Observable.normalized_value.ilike(term),
            Observable.original_value.ilike(term),
        )
    ).limit(limit)

    result = await db.execute(stmt)
    observables = result.scalars().all()

    return ObservableListResponse(
        items=[_format_observable(o) for o in observables],
        total=len(observables),
    )
