"""
CIPHER AI - Security Target & Observable Domain Models
Implements persistent security targets and technical observables with tenant isolation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class TargetType(str, Enum):
    """Supported security target classification types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    CLOUD_ASSET = "cloud_asset"
    URL = "url"


class TargetStatus(str, Enum):
    """Operational lifecycle statuses for security targets."""
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    ENRICHED = "ENRICHED"
    INVESTIGATED = "INVESTIGATED"
    MONITORED = "MONITORED"
    RESOLVED = "RESOLVED"


class ObservableType(str, Enum):
    """Supported observable indicator types."""
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    CVE = "cve"


class SecurityTarget(Base, TimestampMixin):
    """
    Security Target entity representing an asset, endpoint, or infrastructure component
    under security monitoring, investigation, or perimeter defense.
    Strictly isolated per tenant organization.
    """
    __tablename__ = "security_targets"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "target_type",
            "normalized_value",
            name="uq_security_targets_org_type_val",
        ),
        Index("ix_security_targets_org_status", "organization_id", "status"),
        Index("ix_security_targets_org_type", "organization_id", "target_type"),
        Index("ix_security_targets_org_norm", "organization_id", "normalized_value"),
        Index("ix_security_targets_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    normalized_value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )
    original_value: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=TargetStatus.QUEUED.value,
        nullable=False,
        index=True,
    )
    environment: Mapped[str] = mapped_column(
        String(50),
        default="external_threat",
        nullable=False,
    )
    priority: Mapped[str] = mapped_column(
        String(50),
        default="high",
        nullable=False,
    )
    threat_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(
        String(50),
        default="unknown",
        nullable=False,
    )
    risk_level: Mapped[str] = mapped_column(
        String(50),
        default="UNKNOWN",
        nullable=False,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    asn: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    country: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    city: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    open_ports: Mapped[List[int]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    tags: Mapped[List[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
    )
    creator: Mapped[Optional["User"]] = relationship(
        "User",
    )
    observables: Mapped[List["Observable"]] = relationship(
        "Observable",
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Observable(Base, TimestampMixin):
    """
    Observable entity representing a technical atomic indicator (IP, domain, hash, CVE, URL)
    extracted from telemetry, logs, or linked to a parent target asset.
    Strictly isolated per tenant organization.
    """
    __tablename__ = "observables"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "observable_type",
            "normalized_value",
            name="uq_observables_org_type_val",
        ),
        Index("ix_observables_org_type", "organization_id", "observable_type"),
        Index("ix_observables_org_norm", "organization_id", "normalized_value"),
        Index("ix_observables_org_target", "organization_id", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_targets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    observable_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    normalized_value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )
    original_value: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        default="manual",
        nullable=False,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="high",
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="active",
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
    )
    target: Mapped[Optional["SecurityTarget"]] = relationship(
        "SecurityTarget",
        back_populates="observables",
    )
