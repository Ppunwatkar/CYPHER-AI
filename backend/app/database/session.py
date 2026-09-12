"""
CIPHER AI - Database Session & Connection Management
Async SQLAlchemy 2.x engine, connection pooling, and connection health probe.
"""

import asyncio
import logging
import re
import time
from typing import AsyncGenerator, Optional, Tuple
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

logger = logging.getLogger("cipher.database")
settings = get_settings()


def _sanitize_db_error(msg: Optional[str]) -> Optional[str]:
    """Sanitizes sensitive database credentials from error messages."""
    if not msg:
        return msg
    sanitized = re.sub(r":([^:@\s]+)@", r":****@", msg)
    sanitized = re.sub(r"(password=)[^\s;]+", r"\1****", sanitized, flags=re.IGNORECASE)
    return sanitized


# Create Async Engine for PostgreSQL with connection pooling
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency yielding an isolated asynchronous database session.
    Automatically closes the session upon request completion.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_database_connection() -> Tuple[bool, str, float, Optional[str]]:
    """
    Performs a lightweight 'SELECT 1' connection health probe against PostgreSQL.
    Returns:
        tuple of (is_connected: bool, status: str, latency_ms: float, error_message: str | None)
    """
    start_time = time.perf_counter()
    try:
        async with AsyncSessionLocal() as session:
            await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=2.0)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return True, "operational", latency_ms, None
    except asyncio.TimeoutError:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning("Database connection probe timed out after %s ms", latency_ms)
        return False, "unavailable", latency_ms, "Connection timed out after 2.0s"
    except SQLAlchemyError as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        raw_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        error_msg = _sanitize_db_error(raw_msg)
        logger.warning("Database connection probe failed (%s ms): %s", latency_ms, error_msg)
        return False, "unavailable", latency_ms, error_msg
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        error_msg = _sanitize_db_error(str(exc))
        logger.error("Unexpected error during database health check: %s", error_msg)
        return False, "unavailable", latency_ms, error_msg


async def close_database_connections() -> None:
    """Disposes the database connection pool during application shutdown."""
    logger.info("Disposing PostgreSQL connection pool...")
    await engine.dispose()
    logger.info("PostgreSQL connection pool disposed.")
