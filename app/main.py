from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import (
    APIProblemException,
    rfc7807_exception_handler,
    validation_exception_handler,
)
from app.core.logging import logger, setup_logging
from app.core.middlewares import (
    AuditContextMiddleware,
    CybersecurityHeadersMiddleware,
    PayloadSizeLimitMiddleware,
)
from app.db.models import Base
from app.db.seed import seed_roles_and_permissions
from app.db.session import AsyncSessionLocal, engine

tags_metadata = [
    {
        "name": "Health",
        "description": "System health and storage readiness probes.",
    },
    {
        "name": "Observability",
        "description": "Real-time Prometheus metrics endpoint (`/metrics`) for Grafana and SIEM integration.",
    },
    {
        "name": "Proof-of-Work",
        "description": "Cryptographic Proof-of-Work (PoW) SHA-256 challenge generation for front-door anti-bot protection.",
    },
    {
        "name": "Authentication",
        "description": "Zero-Trust OTP Request/Verify, Passwordless/2FA Login, and DAG Token Rotation endpoints.",
    },
    {
        "name": "Users",
        "description": "User profile management and authenticated user context.",
    },
    {
        "name": "Admin",
        "description": "RBAC user administration and role management endpoints.",
    },
]

description_markdown = """
# 🛡️ Enterprise Zero-Trust OTP Authentication REST API

Welcome to the **Zero-Trust OTP Authentication API**, featuring a three-tiered cybersecurity architecture:

1. **Front-Door Proof-of-Work (PoW) Shield**: SHA-256 challenge-response rate limiter protecting perimeter endpoints against automated botnet flooding.
2. **Context-Aware Risk-Based Authentication (RBA) Engine**: Dynamic mathematical entropy scaling ($H = \\log_2(S^L)$) adapting OTP length, character set, and expiration based on real-time risk scores ($R \\in [0, 1]$).
3. **Cryptographic Directed Acyclic Graph (DAG) Token Rotation**: Session family tree tracking (`parent_jti`, `family_id`) with sub-millisecond cascading revocation upon token reuse detection.

---
### 🔒 Security Standards & Compliance
- **Error Handling**: Standardized RFC 7807 (`application/problem+json`) problem details.
- **Privacy**: Strict PII-Zero sanitization (auto-redacting emails, passwords, and tokens in structured logs).
- **Container Hardening**: CIS Docker Benchmark compliant (Non-root user `UID 10001`, `read_only: true`, `cap_drop: ALL`).
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize logging & Seed initial DB roles/permissions
    setup_logging(settings.ENVIRONMENT)
    logger.info(
        "Starting application",
        project_name=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        public_registration=settings.ENABLE_PUBLIC_REGISTRATION,
    )

    # Safely create tables if they do not exist (idempotent across multiple Granian workers)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync_conn: Base.metadata.create_all(sync_conn, checkfirst=True))
    except Exception as exc:
        logger.debug("Table creation checked/initialized by another worker", error=str(exc))

    async with AsyncSessionLocal() as session:
        await seed_roles_and_permissions(session)

    yield

    # Shutdown
    logger.info("Shutting down application")
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=description_markdown,
    version="1.0.0",
    openapi_tags=tags_metadata,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Middlewares
app.add_middleware(CybersecurityHeadersMiddleware)
app.add_middleware(AuditContextMiddleware)
app.add_middleware(PayloadSizeLimitMiddleware)

# RFC 7807 Exception Handlers
app.add_exception_handler(APIProblemException, rfc7807_exception_handler)
app.add_exception_handler(HTTPException, rfc7807_exception_handler)
app.add_exception_handler(StarletteHTTPException, rfc7807_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, rfc7807_exception_handler)

# Routers
app.include_router(api_router, prefix=settings.API_V1_STR)

from app.api.v1.endpoints.dashboard import get_security_dashboard
app.add_api_route("/dashboard", get_security_dashboard, methods=["GET"], include_in_schema=False)


@app.get("/", include_in_schema=False)
async def root_redirect():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "docs": "/docs",
        "dashboard": "/dashboard",
        "api_v1": settings.API_V1_STR,
    }
