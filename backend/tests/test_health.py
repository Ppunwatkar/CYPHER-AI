"""
CIPHER AI - Health & System Diagnostics Tests
Verifies /api/v1/health and /api/v1/system/health contracts and middleware headers.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_contract(async_client: AsyncClient):
    """Verifies that GET /api/v1/health conforms to the HealthResponse contract."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["app"] == "CIPHER AI"
    assert data["version"] == "1.0.0"
    assert data["status"] in ("ok", "degraded")
    assert "timestamp" in data
    assert "database" in data

    db_info = data["database"]
    assert "connected" in db_info
    assert db_info["dialect"] == "postgresql"
    assert db_info["status"] in ("operational", "degraded", "unavailable")
    assert isinstance(db_info["latency_ms"], (int, float))

    # Verify correlation headers
    assert "x-request-id" in response.headers
    assert "x-response-time" in response.headers


@pytest.mark.asyncio
async def test_system_health_endpoint_contract(async_client: AsyncClient):
    """
    Verifies that GET /api/v1/system/health returns connectors matching
    the frontend SystemStatusModal ServiceHealthStatus format.
    """
    response = await async_client.get("/api/v1/system/health")
    assert response.status_code == 200

    data = response.json()
    assert data["overallStatus"] in ("Operational", "Degraded", "Unavailable")
    assert "ONLINE" in data["activeConnectorsCount"]
    assert "timestamp" in data
    assert "services" in data
    assert isinstance(data["services"], list)
    assert len(data["services"]) == 8

    # Verify service names and categories match frontend types
    service_names = [s["service"] for s in data["services"]]
    assert any("AI Model Gateway" in name for name in service_names)
    assert any("RAG Vector" in name for name in service_names)
    assert any("Telemetry & Target Store" in name for name in service_names)
    assert any("PostgreSQL Primary Database" in name for name in service_names)
    assert any("AbuseIPDB" in name for name in service_names)
    assert any("Shodan" in name for name in service_names)
    assert any("VirusTotal" in name for name in service_names)
    assert any("NVD" in name for name in service_names)

    # Check properties of each service item
    for item in data["services"]:
        assert "service" in item
        assert item["category"] in ("AI Model", "Threat Intel", "Vulnerability", "Identity", "Storage")
        assert item["status"] in ("Operational", "Degraded", "Unavailable", "Not Configured", "Rate Limited")
        assert isinstance(item["latencyMs"], int)
        assert isinstance(item["notes"], str)
        assert isinstance(item["isSimulated"], bool)


@pytest.mark.asyncio
async def test_request_id_propagation(async_client: AsyncClient):
    """Verifies that an incoming X-Request-ID header is preserved and returned."""
    custom_id = "test-secops-req-4492-alpha"
    response = await async_client.get("/api/v1/health", headers={"X-Request-ID": custom_id})

    assert response.status_code == 200
    assert response.headers.get("x-request-id") == custom_id


@pytest.mark.asyncio
async def test_root_endpoint_metadata(async_client: AsyncClient):
    """Verifies root route returns platform metadata."""
    response = await async_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "CIPHER AI"
    assert data["health"] == "/api/v1/health"
    assert data["systemHealth"] == "/api/v1/system/health"
