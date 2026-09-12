"""
CIPHER AI - FastAPI Application Server
Entry point featuring structured logging, safe CORS, request ID correlation,
global exception handling, and database lifecycle management.
"""

import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import api_router
from app.config import get_settings
from app.database.session import check_database_connection, close_database_connections

# Configure root logger
settings = get_settings()
log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("cipher.server")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan managing startup validation and shutdown resource cleanup."""
    # Startup
    logger.info("==================================================")
    logger.info("  %s v%s - Initializing Backend", settings.APP_NAME, settings.APP_VERSION)
    logger.info("  Environment : %s", settings.ENVIRONMENT)
    logger.info("  CORS Origins: %s", settings.CORS_ORIGINS)
    logger.info("==================================================")

    # Verify Database Connection
    is_connected, db_status, latency_ms, error = await check_database_connection()
    if is_connected:
        logger.info("PostgreSQL Database connected successfully (latency: %s ms).", latency_ms)
    else:
        logger.warning(
            "PostgreSQL Database unreachable on startup (%s ms): %s. "
            "Server will continue running; database endpoints will report degraded.",
            latency_ms,
            error,
        )

    yield

    # Shutdown
    logger.info("Shutting down %s backend...", settings.APP_NAME)
    await close_database_connections()
    logger.info("Shutdown complete.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Cybersecurity Intelligence Copilot & Autonomous Threat Investigation Platform API",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
    lifespan=lifespan,
)


# ==============================================================================
# Middlewares
# ==============================================================================

class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """
    Assigns or preserves a unique X-Request-ID for every HTTP request.
    Enables end-to-end telemetry tracking and audit trail correlation.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID")
        if not request_id or len(request_id) > 64:
            request_id = str(uuid.uuid4())

        request.state.request_id = request_id

        start_time = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                "[%s] %s %s - Unhandled error after %s ms: %s",
                request_id,
                request.method,
                request.url.path,
                duration_ms,
                exc,
            )
            raise exc

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms}ms"

        # Structured request audit line
        logger.info(
            "[%s] %s %s %s (%s ms)",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response


# Attach Request Correlation Middleware
app.add_middleware(RequestCorrelationMiddleware)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Enforces enterprise HTTP security response headers across all responses.
    Mitigates MIME sniffing, clickjacking, unencrypted transport, and embedding.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Baseline hardening headers (OWASP ASVS 14.4)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
        )

        # Prevent browser caching of sensitive API responses
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        # HSTS in production or HTTPS connections
        if settings.is_production or request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Enforces Cross-Site Request Forgery (CSRF) protection for mutating operations.
    Validates Origin headers and requires anti-CSRF verification tokens or custom
    headers on state-changing requests utilizing ambient cookie authentication.
    """
    MUTATING_METHODS = frozenset(["POST", "PUT", "PATCH", "DELETE"])
    EXEMPT_PATHS = frozenset(["/api/v1/auth/login", "/api/v1/auth/register"])

    async def dispatch(self, request: Request, call_next):
        if request.method in self.MUTATING_METHODS and request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            auth_header = request.headers.get("authorization")
            has_auth_cookies = bool(
                request.cookies.get("access_token") or request.cookies.get("refresh_token")
            )

            # 1. If Origin header is present, it MUST match configured CORS origins
            if origin:
                clean_origin = origin.rstrip("/")
                allowed_origins = [o.rstrip("/") for o in settings.CORS_ORIGINS]
                if clean_origin not in allowed_origins:
                    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
                    logger.warning("[%s] CSRF blocked: unauthorized origin '%s'", request_id, origin)
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "success": False,
                            "error": {
                                "code": 403,
                                "message": "CSRF verification failed: unauthorized request origin.",
                            },
                            "requestId": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )

            # 2. If cookie authentication is utilized without an explicit Bearer header,
            # require custom client header or matching Origin/Referer on protected routes
            if (
                has_auth_cookies
                and not (auth_header and auth_header.startswith("Bearer "))
                and request.url.path not in self.EXEMPT_PATHS
            ):
                has_custom_header = bool(
                    request.headers.get("x-requested-with")
                    or request.headers.get("x-csrf-token")
                    or request.headers.get("x-cipher-client")
                )
                valid_origin = origin and origin.rstrip("/") in [o.rstrip("/") for o in settings.CORS_ORIGINS]
                valid_referer = referer and any(
                    referer.startswith(allowed) for allowed in settings.CORS_ORIGINS
                )

                if not (has_custom_header or valid_origin or valid_referer):
                    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
                    logger.warning(
                        "[%s] CSRF blocked: cookie-authenticated mutating request missing custom header/origin",
                        request_id,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "success": False,
                            "error": {
                                "code": 403,
                                "message": "CSRF verification failed: missing verification header or authorized origin for cookie-authenticated request.",
                            },
                            "requestId": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )

        return await call_next(request)


# Attach Security Middlewares
app.add_middleware(CSRFProtectionMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Attach Safe CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time"],
)


# ==============================================================================
# Global Exception Handlers
# ==============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Standardized error envelope for HTTP exceptions."""
    request_id = getattr(request.state, "request_id", "unknown")
    response_headers = {"X-Request-ID": request_id}
    if exc.headers:
        response_headers.update(exc.headers)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
            },
            "detail": exc.detail,
            "requestId": request_id,
        },
        headers=response_headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Standardized error envelope for Pydantic schema validation errors."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.warning("[%s] Schema validation failure on %s: %s", request_id, request.url.path, exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": {
                "code": 422,
                "message": "Input validation failed",
                "details": exc.errors(),
            },
            "requestId": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catches all unhandled exceptions without leaking server stack secrets."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.critical("[%s] Fatal unhandled exception on %s: %s", request_id, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": 500,
                "message": "An internal server error occurred. Please reference requestId in audit logs.",
            },
            "requestId": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


# ==============================================================================
# Route Registrations
# ==============================================================================

app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def root():
    """Root metadata pointer."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs" if not settings.is_production else None,
        "health": "/api/v1/health",
        "systemHealth": "/api/v1/system/health",
    }
