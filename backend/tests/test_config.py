"""
CIPHER AI - Configuration & Security Validation Tests
Verifies settings parsing, safe CORS validation, and database URL conversion.
"""

import pytest
from pydantic import ValidationError
from app.config import Settings


def test_default_configuration():
    """Verifies default settings structure."""
    settings = Settings()
    assert settings.APP_NAME == "CIPHER AI"
    assert settings.APP_VERSION == "1.0.0"
    assert settings.PORT == 8000
    assert "postgresql+asyncpg" in settings.DATABASE_URL
    assert "postgresql+psycopg" in settings.sync_database_url


def test_cors_origin_json_parsing():
    """Verifies parsing of JSON array CORS origins."""
    settings = Settings(
        CORS_ORIGINS='["https://soc.defense.internal", "https://cipher.defense.corp"]'
    )
    assert len(settings.CORS_ORIGINS) == 2
    assert "https://soc.defense.internal" in settings.CORS_ORIGINS
    assert "https://cipher.defense.corp" in settings.CORS_ORIGINS


def test_cors_origin_comma_separated_parsing():
    """Verifies parsing of comma-separated string CORS origins."""
    settings = Settings(
        CORS_ORIGINS="http://localhost:3000, http://localhost:5173"
    )
    assert len(settings.CORS_ORIGINS) == 2
    assert "http://localhost:3000" in settings.CORS_ORIGINS


def test_production_wildcard_cors_rejected():
    """Verifies that wildcard CORS is strictly prohibited in production."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            CORS_ORIGINS=["*"],
        )
    assert "Wildcard CORS origin '*' is strictly prohibited" in str(exc_info.value)


def test_staging_wildcard_cors_rejected():
    """Verifies that wildcard CORS is strictly prohibited in staging."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="staging",
            CORS_ORIGINS=["*"],
        )
    assert "Wildcard CORS origin '*' is strictly prohibited" in str(exc_info.value)
