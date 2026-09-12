"""
CIPHER AI - Identity & Security Classification Enums
Explicit separation between RBAC roles, security clearance, and TLP data-sharing markings.
"""

from enum import Enum


class OrganizationStatus(str, Enum):
    """Lifecycle status of a tenant organization."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class UserStatus(str, Enum):
    """Lifecycle status of a platform user."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    INVITED = "invited"
    INACTIVE = "inactive"


class ClearanceLevel(str, Enum):
    """
    Security clearance authorization for personnel / security analysts.
    Represents authorization level to access classified security assets and findings.

    HIERARCHICAL ORDER:
    UNCLASSIFIED (0) < RESTRICTED (1) < CONFIDENTIAL (2) < SECRET (3) < TOP_SECRET (4)

    SECURITY ARCHITECTURE DESIGN PRINCIPLE:
    This represents personnel security authorization. It must NOT be confused with
    or conflated with TLP (Traffic Light Protocol), which is exclusively for data-sharing classification.
    """
    UNCLASSIFIED = "UNCLASSIFIED"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"  # nosec B105 - Clearance level classification, not a credential
    TOP_SECRET = "TOP_SECRET"  # nosec B105 - Clearance level classification, not a credential

    @property
    def level_rank(self) -> int:
        """Numeric rank for hierarchical clearance comparison."""
        ranks = {
            ClearanceLevel.UNCLASSIFIED: 0,
            ClearanceLevel.RESTRICTED: 1,
            ClearanceLevel.CONFIDENTIAL: 2,
            ClearanceLevel.SECRET: 3,
            ClearanceLevel.TOP_SECRET: 4,
        }
        return ranks[self]

    def satisfies(self, required: "ClearanceLevel") -> bool:
        """Returns True if this clearance level meets or exceeds the required level."""
        return self.level_rank >= required.level_rank


class TLPClassification(str, Enum):
    """
    FIRST Standards Traffic Light Protocol (TLP 2.0) data-sharing markings.

    CRITICAL SECURITY DESIGN PRINCIPLE:
    TLP is strictly a data-sharing classification mechanism indicating who may receive
    and redistribute specific threat intelligence artifacts.

    IT MUST NEVER BE TREATED AS A USER'S AUTHORIZATION OR CLEARANCE LEVEL.
    - Users have RBAC Roles (defining actions/tools they may execute).
    - Users have Security Clearance (ClearanceLevel, defining confidentiality access).
    - Threat data and intelligence reports carry TLP markings (TLPClassification).
    """
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"
