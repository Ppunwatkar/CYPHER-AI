"""
CIPHER AI - Health & Diagnostics Schemas
Defines request and response models for system health and service telemetry.
"""

from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class DatabaseHealth(BaseModel):
    """Database connection status metrics."""
    connected: bool
    status: str = Field(..., description="'operational', 'degraded', or 'unavailable'")
    latency_ms: float
    dialect: str = "postgresql"
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Simple application and database health check."""
    status: str = Field(..., description="'ok' or 'degraded'")
    app: str = "CIPHER AI"
    version: str = "1.0.0"
    environment: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    database: DatabaseHealth


class ServiceHealthItem(BaseModel):
    """
    Individual service connector status item.
    Matches frontend ServiceHealthStatus interface in src/types.ts.
    """
    service: str
    category: str = Field(
        ...,
        description="'AI Model', 'Threat Intel', 'Vulnerability', 'Identity', 'Storage'"
    )
    status: str = Field(
        ...,
        description="'Operational', 'Degraded', 'Unavailable', 'Not Configured', 'Rate Limited'"
    )
    latencyMs: int
    notes: str
    isSimulated: bool = False


class SystemHealthResponse(BaseModel):
    """
    Detailed system health report for all security services and connectors.
    Consumable directly by frontend SystemStatusModal.
    """
    overallStatus: str = Field(..., description="'Operational', 'Degraded', 'Unavailable'")
    activeConnectorsCount: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    services: List[ServiceHealthItem]
