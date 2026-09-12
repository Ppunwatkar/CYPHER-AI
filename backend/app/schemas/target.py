"""
CIPHER AI - Target & Observable Pydantic DTO Schemas
Provides serialization and validation with snake_case and camelCase compatibility.
"""

from datetime import datetime
from typing import Any, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class TargetCreateRequest(BaseModel):
    """Payload for creating a single security target."""
    model_config = ConfigDict(populate_by_name=True)

    value: str = Field(..., description="Target indicator value (e.g. IP, domain, CIDR, URL)")
    type: Optional[str] = Field(None, description="Optional target type; auto-detected if omitted")
    label: Optional[str] = Field(None, description="Human-readable label for target asset")
    environment: Optional[str] = Field("external_threat", description="Environment classification")
    priority: Optional[str] = Field("high", description="Investigation priority: critical, high, medium, low")
    threat_score: Optional[int] = Field(0, alias="threatScore", ge=0, le=100)
    verdict: Optional[str] = Field("unknown", description="Initial verdict: malicious, suspicious, benign, unknown")
    risk_level: Optional[str] = Field("UNKNOWN", alias="riskLevel")
    confidence: Optional[int] = Field(0, ge=0, le=100)
    status: Optional[str] = Field("QUEUED", description="Initial status: QUEUED, DISCOVERED, etc.")
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    open_ports: Optional[List[int]] = Field(default_factory=list, alias="openPorts")
    tags: Optional[List[str]] = Field(default_factory=list)
    notes: Optional[str] = None
    description: Optional[str] = None


class TargetUpdateRequest(BaseModel):
    """Payload for partially modifying an existing security target."""
    model_config = ConfigDict(populate_by_name=True)

    label: Optional[str] = None
    environment: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    threat_score: Optional[int] = Field(None, alias="threatScore", ge=0, le=100)
    verdict: Optional[str] = None
    risk_level: Optional[str] = Field(None, alias="riskLevel")
    confidence: Optional[int] = Field(None, ge=0, le=100)
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    open_ports: Optional[List[int]] = Field(None, alias="openPorts")
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    description: Optional[str] = None


class TargetResponse(BaseModel):
    """Complete sanitized target response entity."""
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    id: str
    organization_id: str
    name: str = Field(..., alias="label")
    label: str
    target_type: str = Field(..., alias="type")
    type: str
    normalized_value: str = Field(..., alias="value")
    value: str
    original_value: str
    status: str
    environment: str
    priority: str
    threat_score: int = Field(..., alias="threatScore")
    threatScore: int
    verdict: str
    risk_level: str = Field(..., alias="riskLevel")
    riskLevel: str
    confidence: int
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list, alias="openPorts")
    openPorts: List[int]
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    created_at: datetime = Field(..., alias="addedAt")
    addedAt: str
    updated_at: datetime
    last_scanned_at: Optional[datetime] = Field(None, alias="lastScannedAt")
    lastScannedAt: Optional[str] = None


class TargetListResponse(BaseModel):
    """Paginated response containing target items."""
    model_config = ConfigDict(populate_by_name=True)

    items: List[TargetResponse]
    total: int
    limit: int
    offset: int


class TargetBulkCreateRequest(BaseModel):
    """Bulk ingestion payload for multiple targets."""
    model_config = ConfigDict(populate_by_name=True)

    targets: List[TargetCreateRequest]


class TargetBulkCreateResponse(BaseModel):
    """Result of bulk ingestion operation."""
    model_config = ConfigDict(populate_by_name=True)

    created_count: int
    skipped_count: int
    items: List[TargetResponse]
    errors: List[dict]


class ObservableCreateRequest(BaseModel):
    """Payload for creating an observable associated with a target."""
    model_config = ConfigDict(populate_by_name=True)

    value: str = Field(..., description="Observable indicator string")
    type: Optional[str] = Field(None, description="Optional observable type")
    source: Optional[str] = Field("manual", description="Observation source")
    confidence: Optional[int] = Field(80, ge=0, le=100)
    severity: Optional[str] = Field("high", description="critical, high, medium, low")
    status: Optional[str] = Field("active", description="active, investigating, blocked, mitigated")


class ObservableResponse(BaseModel):
    """Complete sanitized observable response entity."""
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    id: str
    organization_id: str
    target_id: Optional[str] = None
    observable_type: str = Field(..., alias="type")
    type: str
    normalized_value: str = Field(..., alias="value")
    value: str
    original_value: str
    source: str
    confidence: int
    severity: str
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class ObservableListResponse(BaseModel):
    """Response containing list of observables."""
    model_config = ConfigDict(populate_by_name=True)

    items: List[ObservableResponse]
    total: int
