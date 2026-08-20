import time
import uuid
from typing import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces strict payload size limits on incoming HTTP requests.
    Mitigates Memory Exhaustion, Buffer Overflow, and Denial of Service (DoS) attacks.
    Examines Content-Length header in O(1) time before consuming server resources.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("Content-Length")

            # Higher payload limit for file upload endpoints vs standard JSON APIs
            if "upload-csv" in request.url.path or "file" in request.url.path:
                max_bytes = settings.MAX_FILE_UPLOAD_SIZE_MB * 1024 * 1024
            else:
                max_bytes = settings.MAX_PAYLOAD_SIZE_MB * 1024 * 1024

            if content_length is not None:
                try:
                    if int(content_length) > max_bytes:
                        limit_mb = max_bytes / (1024 * 1024)
                        logger.warning(
                            "Payload size limit exceeded (HTTP 413)",
                            content_length=content_length,
                            max_bytes=max_bytes,
                            path=request.url.path,
                        )
                        return JSONResponse(
                            status_code=413,
                            content={
                                "type": "https://errors.enterprise-otp.io/v1/payload-too-large",
                                "title": "Payload Too Large",
                                "status": 413,
                                "detail": f"El cuerpo de la petición excede el límite máximo permitido ({limit_mb} MB).",
                                "instance": request.url.path,
                            },
                        )
                except ValueError:
                    pass

        return await call_next(request)


class AuditContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware that generates/extracts X-Request-ID (UUIDv4)
    and logs full request/response audit trails with process timing.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.perf_counter()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
        )

        try:
            response = await call_next(request)
            process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time-Ms"] = str(process_time_ms)

            # Record metrics & audit logs (Excludes internal telemetry polling from polluting counts)
            telemetry_paths = [
                "/api/v1/metrics",
                "/metrics",
                "/api/v1/dashboard/events",
                "/dashboard/events",
                "/api/v1/health",
                "/health",
                "/favicon.ico",
            ]
            is_telemetry = any(
                request.url.path == p or request.url.path.endswith(p) for p in telemetry_paths
            )

            if not is_telemetry:
                from app.core.metrics import metrics_collector
                metrics_collector.record_http_request(
                    request.method, request.url.path, response.status_code
                )

                # Audit Log for non-telemetry HTTP activity
                logger.info(
                    "API Activity Audit",
                    status_code=response.status_code,
                    process_time_ms=process_time_ms,
                    user_agent=user_agent,
                )
            return response
        except Exception as exc:
            process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                "API Activity Audit (Failed Request)",
                error=str(exc),
                process_time_ms=process_time_ms,
                user_agent=user_agent,
                exc_info=True,
            )
            raise exc


class CybersecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that injects recommended cybersecurity headers on every HTTP response.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Content Security Policy (Allows CDN assets for Swagger UI, ReDoc & Interactive Dashboard)
        if request.url.path in [
            "/docs",
            "/redoc",
            f"{settings.API_V1_STR}/openapi.json",
            f"{settings.API_V1_STR}/dashboard",
            "/dashboard",
            "/",
        ]:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
                "frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none';"
            )

        return response
