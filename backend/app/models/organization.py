"""
CIPHER AI - Organization Domain Model
Defines tenant boundary for secure multi-tenancy and organization data isolation.
"""

from typing import TYPE_CHECKING, List
import uuid

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.enums import OrganizationStatus

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.role import Role


class Organization(Base, TimestampMixin):
    """
    Tenant boundary entity for CIPHER AI.
    All users and operational data belong to an organization for multi-tenant isolation.
    """
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=OrganizationStatus.ACTIVE.value,
        nullable=False,
        index=True,
    )

    # Relationships
    users: Mapped[List["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    roles: Mapped[List["Role"]] = relationship(
        "Role",
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def is_active(self) -> bool:
        """Returns True if the organization is active."""
        return self.status == OrganizationStatus.ACTIVE.value
