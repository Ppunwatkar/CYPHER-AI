"""
CIPHER AI - API Routes Package
"""

from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.targets import router as targets_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router, tags=["Health & Diagnostics"])
api_router.include_router(auth_router)
api_router.include_router(targets_router)

__all__ = ["api_router"]
