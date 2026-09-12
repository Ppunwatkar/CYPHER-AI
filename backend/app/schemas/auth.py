"""
CIPHER AI - Authentication Request & Response Schemas
Validates identity inputs, enforces password complexity, and sanitizes output payloads.
"""

import re
from datetime import datetime
from typing import List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ClearanceLevel
from app.security.password import validate_password_policy

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class RegisterRequest(BaseModel):
    """Payload for registering a new security analyst / operator account."""
    email: str = Field(..., max_length=255, description="Analyst email address")
    password: str = Field(..., min_length=8, max_length=128, description="Argon2id compliant password")
    display_name: str = Field(..., min_length=2, max_length=100, description="Full analyst name")
    organization_name: Optional[str] = Field(
        default="Global SOC Sentinel Unit",
        max_length=255,
        description="Tenant organization name",
    )
    role_name: Optional[str] = Field(
        default="Incident Responder",
        max_length=100,
        description="Initial RBAC role",
    )
    clearance_level: Optional[ClearanceLevel] = Field(
        default=ClearanceLevel.UNCLASSIFIED,
        description="Personnel security clearance authorization",
    )

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Email must be a string.")
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email address format.")
        return cleaned

    @field_validator("display_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 2:
            raise ValueError("Display name must be at least 2 characters long.")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        is_valid, err = validate_password_policy(v)
        if not is_valid:
            raise ValueError(err)
        return v


class LoginRequest(BaseModel):
    """Payload for authenticating existing credentials."""
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower() if isinstance(v, str) else v



class UserAuthResponse(BaseModel):
    """
    Sanitized user identity representation returned to authenticated clients.
    Excludes password hashes, secret keys, or internal operational states.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str
    organization_id: uuid.UUID
    organization_name: str
    status: str
    clearance_level: str
    roles: List[str]
    permissions: List[str]
    created_at: datetime


class AuthStatusResponse(BaseModel):
    """Simple confirmation response for logout or session actions."""
    message: str
    authenticated: bool
    user: Optional[UserAuthResponse] = None
