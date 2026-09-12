"""
CIPHER AI - Application Configuration
Validates environment settings at startup using Pydantic Settings.
"""

import json
from functools import lru_cache
from typing import Any, List, Optional
from pydantic import field_validator, ValidationInfo, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Core application settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General Application
    APP_NAME: str = "CIPHER AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # Database Settings
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_DB: str = "cipher_db"
    POSTGRES_PORT: int = 5432
    POSTGRES_HOST: str = "localhost"

    # Primary PostgreSQL Connection URL
    # Must use asyncpg driver for async SQLAlchemy: postgresql+asyncpg://user:pass@host:port/dbname
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/cipher_db"

    @model_validator(mode="after")
    def assemble_database_url(self) -> "Settings":
        """Ensures DATABASE_URL incorporates POSTGRES_PASSWORD if provided and DATABASE_URL is default."""
        if self.POSTGRES_PASSWORD and (
            self.DATABASE_URL == "postgresql+asyncpg://postgres:postgres@localhost:5432/cipher_db"
            or not self.DATABASE_URL
        ):
            self.DATABASE_URL = (
                f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
                f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        return self

    # Database Pool Settings
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: float = 30.0
    DB_POOL_PRE_PING: bool = True

    # JWT & Authentication Security
    JWT_SECRET_KEY: str = "cipher-secops-dev-signing-key-32-chars-minimum-replace-prod"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    AUTH_RATE_LIMIT_MAX_ATTEMPTS: int = 5
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 300

    @property
    def is_cookie_secure(self) -> bool:
        """Enforces Secure cookie attribute in production or when explicitly set."""
        return self.COOKIE_SECURE or self.is_production

    # Request & Timeout Controls
    REQUEST_TIMEOUT_SECONDS: int = 30

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any, info: ValidationInfo) -> List[str]:
        """Parses CORS origins from JSON list, comma-separated string, or list."""
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            # Comma-separated fallback
            return [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_production_cors(cls, origins: List[str], info: ValidationInfo) -> List[str]:
        """Disallows wildcard CORS in production/staging environments."""
        env = info.data.get("ENVIRONMENT", "development").lower()
        if env in ("production", "staging") and "*" in origins:
            raise ValueError(
                "Wildcard CORS origin '*' is strictly prohibited in production and staging environments."
            )
        return origins

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, key: str, info: ValidationInfo) -> str:
        """Enforces minimum 32-character length and prohibits default dev keys in production/staging."""
        if len(key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long.")
        env = info.data.get("ENVIRONMENT", "development").lower()
        weak_tokens = ["dev-signing-key", "secret", "change-me", "replace-prod", "test-secret"]
        if env in ("production", "staging"):
            key_lower = key.lower()
            if any(token in key_lower for token in weak_tokens):
                raise ValueError(
                    f"Insecure default JWT_SECRET_KEY detected in {env} environment. "
                    "You must configure a cryptographically random 256-bit secret key."
                )
        return key

    @property
    def sync_database_url(self) -> str:
        """Returns a synchronous database URL for Alembic migrations."""
        url = self.DATABASE_URL
        if "+asyncpg" in url:
            return url.replace("+asyncpg", "+psycopg")
        return url

    @property
    def is_production(self) -> bool:
        """Returns True if running in production."""
        return self.ENVIRONMENT.lower() == "production"


@lru_cache()
def get_settings() -> Settings:
    """Returns a cached instance of validated settings."""
    return Settings()
