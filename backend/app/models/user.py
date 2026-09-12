"""
CIPHER AI - User Domain Model
Represents platform users with organization binding, RBAC roles, and security clearance.
"""

from typing import TYPE_CHECKING, List
import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.enums import ClearanceLevel, UserStatus

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.role import Role
    from app.models.session import UserSession


class User(Base, TimestampMixin):
    """
    Platform User entity bounded strictly by Organization.

    SECURITY DESIGN:
    - User has RBAC roles via user_roles (defining permitted actions).
    - User has security clearance via clearance_level (defining data classification access).
    - Password is encrypted using Argon2id with strong salt; plaintext is never persisted.
    """
    __tablename__ = "users"

    __table_args__ = (
        Index("ix_users_org_status", "organization_id", "status"),
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
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="",
        server_default="",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=UserStatus.ACTIVE.value,
        nullable=False,
        index=True,
    )
    clearance_level: Mapped[str] = mapped_column(
        String(50),
        default=ClearanceLevel.UNCLASSIFIED.value,
        nullable=False,
        index=True,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="users",
    )
    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="user_roles",
        back_populates="users",
        lazy="selectin",
    )
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def clearance(self) -> ClearanceLevel:
        """Returns strongly typed ClearanceLevel enum."""
        return ClearanceLevel(self.clearance_level)

    @property
    def is_active(self) -> bool:
        """Returns True if user status is active."""
        return self.status == UserStatus.ACTIVE.value

    def has_role(self, role_name: str) -> bool:
        """Checks if user possesses a given role name."""
        return any(r.name == role_name for r in self.roles)

    def has_permission(self, permission_key: str) -> bool:
        """Checks if user possesses a given permission key across all assigned roles."""
        return any(role.has_permission(permission_key) for role in self.roles)

    def has_clearance(self, required_clearance: ClearanceLevel) -> bool:
        """Evaluates whether user meets or exceeds the required clearance level."""
        return self.clearance.satisfies(required_clearance)
