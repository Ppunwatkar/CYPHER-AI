"""
CIPHER AI - Test Configuration & Fixtures
Async test client using httpx and FastAPI ASGI transport.
"""

import sys
from pathlib import Path
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure backend root is on sys.path
backend_root = Path(__file__).resolve().parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from app.config import Settings, get_settings
from app.main import app


@pytest.fixture
def test_settings() -> Settings:
    """Provides isolated test settings."""
    return Settings(
        APP_NAME="CIPHER AI (Test)",
        ENVIRONMENT="development",
        DEBUG=True,
        CORS_ORIGINS=["http://localhost:3000"],
        DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/cipher_test_db",
    )


from app.security.rate_limiter import (
    login_rate_limiter,
    registration_rate_limiter,
    refresh_rate_limiter,
)


@pytest.fixture(autouse=True)
def reset_all_rate_limiters():
    """Resets all sliding-window rate limiters before and after each test."""
    login_rate_limiter.reset_all()
    registration_rate_limiter.reset_all()
    refresh_rate_limiter.reset_all()
    yield
    login_rate_limiter.reset_all()
    registration_rate_limiter.reset_all()
    refresh_rate_limiter.reset_all()


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Provides an asynchronous HTTP test client bound to the FastAPI app."""
    transport = ASGITransport(app=app)
    headers = {
        "Origin": "http://localhost:3000",
        "X-Requested-With": "XMLHttpRequest",
    }
    async with AsyncClient(transport=transport, base_url="http://localhost:3000", headers=headers) as client:
        yield client


@pytest_asyncio.fixture(autouse=True)
async def cleanup_db_engine():
    """Disposes engine connection pool between test event loops to prevent cross-loop reuse."""
    yield
    from app.database.session import engine
    await engine.dispose()

