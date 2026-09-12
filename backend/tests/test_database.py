"""
CIPHER AI - Database Architecture & Connection Tests
Verifies SQLAlchemy 2.x Declarative Base, conventions, and probe resilience.
"""

import pytest
from app.database.base import Base, POSTGRES_NAMING_CONVENTION
from app.database.session import check_database_connection


def test_base_metadata_naming_conventions():
    """Verifies that Base metadata uses explicit PostgreSQL constraint naming conventions."""
    conventions = Base.metadata.naming_convention
    assert conventions["pk"] == "pk_%(table_name)s"
    assert conventions["fk"] == "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
    assert conventions["uq"] == "uq_%(table_name)s_%(column_0_name)s"
    assert conventions["ix"] == "ix_%(column_0_label)s"


@pytest.mark.asyncio
async def test_database_connection_probe_resilience():
    """
    Verifies that check_database_connection returns a structured tuple
    and does not crash or raise unhandled exceptions when PostgreSQL is unreachable.
    """
    is_connected, status_str, latency_ms, error = await check_database_connection()

    assert isinstance(is_connected, bool)
    assert status_str in ("operational", "unavailable")
    assert isinstance(latency_ms, (int, float))
    assert latency_ms >= 0

    if not is_connected:
        assert error is not None
        assert len(error) > 0
    else:
        assert error is None
