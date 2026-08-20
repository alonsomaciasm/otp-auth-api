from typing import Any, Dict, Optional
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import structlog

logger = structlog.get_logger()


class APIProblemException(HTTPException):
    """
    Base enterprise exception class adhering to RFC 7807 (Problem Details for HTTP APIs).
    """

    def __init__(
        self,
        status_code: int,
        title: str,
        detail: str,
        type_uri: str = "about:blank",
        extra: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.title = title
        self.type_uri = type_uri
        self.extra = extra or {}


class AuthenticationException(APIProblemException):
    def __init__(self, detail: str = "Authentication credentials were invalid or missing.", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Authentication Error",
            detail=detail,
            extra=extra,
        )


class ForbiddenException(APIProblemException):
    def __init__(self, detail: str = "You do not have permission to perform this action.", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            title="Forbidden Access",
            detail=detail,
            extra=extra,
        )


class NotFoundException(APIProblemException):
    def __init__(self, detail: str = "The requested resource was not found.", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            title="Resource Not Found",
            detail=detail,
            extra=extra,
        )


class RateLimitException(APIProblemException):
    def __init__(self, detail: str = "Rate limit exceeded. Please try again later.", retry_after_seconds: int = 60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            title="Rate Limit Exceeded",
            detail=detail,
            extra={"retry_after_seconds": retry_after_seconds},
        )


async def rfc7807_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"

    if isinstance(exc, APIProblemException):
        problem = {
            "type": exc.type_uri,
            "title": exc.title,
            "status": exc.status_code,
            "detail": exc.detail,
            "instance": request.url.path,
        }
        if exc.extra:
            problem.update(exc.extra)

        logger.warning(
            "API problem exception occurred",
            status_code=exc.status_code,
            title=exc.title,
            detail=exc.detail,
            path=request.url.path,
            client_ip=client_ip,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=problem,
            media_type="application/problem+json",
        )

    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        problem = {
            "type": "about:blank",
            "title": "HTTP Error",
            "status": exc.status_code,
            "detail": str(exc.detail),
            "instance": request.url.path,
        }
        logger.warning(
            "HTTP exception occurred",
            status_code=exc.status_code,
            detail=str(exc.detail),
            path=request.url.path,
            client_ip=client_ip,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=problem,
            media_type="application/problem+json",
        )

    # Uncaught 500 Internal Server Error fallback
    logger.error(
        "Unhandled internal server error",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path,
        client_ip=client_ip,
        exc_info=True,
    )

    problem = {
        "type": "about:blank",
        "title": "Internal Server Error",
        "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "detail": "An unexpected error occurred on the server. Please contact system administrator.",
        "instance": request.url.path,
    }
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem,
        media_type="application/problem+json",
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    formatted_errors = []
    for err in exc.errors():
        formatted_errors.append({
            "field": " -> ".join([str(loc) for loc in err.get("loc", [])]),
            "message": err.get("msg"),
            "type": err.get("type"),
        })

    problem = {
        "type": "about:blank",
        "title": "Unprocessable Entity (Validation Error)",
        "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "detail": "Input validation failed. Please check the provided fields.",
        "instance": request.url.path,
        "invalid_params": formatted_errors,
    }

    logger.warning(
        "Input validation error",
        path=request.url.path,
        client_ip=client_ip,
        invalid_params=formatted_errors,
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem,
        media_type="application/problem+json",
    )
