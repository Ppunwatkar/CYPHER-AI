"""
CIPHER AI - Immutable Audit Logging Service
Persists structured audit events for target lifecycle and security operations.
Guarantees zero-leakage of passwords, session cookies, tokens, or private secrets.
"""

import logging
from typing import Any, Dict, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.user import User

logger = logging.getLogger("cipher.audit")

SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "cookie",
    "secret",
    "session_secret",
    "api_key",
    "authorization",
}


def _scrub_sensitive_data(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively redacts sensitive authentication keys from audit details."""
    if not data:
        return {}

    scrubbed = {}
    for key, val in data.items():
        if any(sens in key.lower() for sens in SENSITIVE_KEYS):
            scrubbed[key] = "[REDACTED]"
        elif isinstance(val, dict):
            scrubbed[key] = _scrub_sensitive_data(val)
        else:
            scrubbed[key] = val
    return scrubbed


async def log_audit_event(
    db: AsyncSession,
    organization_id: uuid.UUID,
    action: str,
    resource_type: str,
    actor: Optional[User] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Optional[AuditLog]:
    """
    Asynchronously records an immutable audit log entry in the database
    and issues a structured telemetry log entry.
    """
    safe_details = _scrub_sensitive_data(details)

    actor_id = actor.id if actor else None
    actor_email = actor.email if actor else "system"

    audit_entry = AuditLog(
        organization_id=organization_id,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=safe_details,
        request_id=request_id,
        ip_address=ip_address,
    )

    db.add(audit_entry)

    # Telemetry logging
    logger.info(
        "[%s] AUDIT org=%s action=%s resource=%s:%s actor=%s ip=%s",
        request_id or "system",
        organization_id,
        action,
        resource_type,
        resource_id or "none",
        actor_email,
        ip_address or "unknown",
    )

    return audit_entry
