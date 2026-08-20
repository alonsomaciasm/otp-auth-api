from fastapi import Request
from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.services.storage import BaseStorage, storage_service


class RateLimiter:
    def __init__(self, storage: BaseStorage = storage_service):
        self.storage = storage

    async def check_rate_limit(
        self, key: str, max_requests: int = 3, window_seconds: int = 60
    ) -> None:
        rate_key = f"rate_limit:{key}"
        count = await self.storage.incr(rate_key, ttl_seconds=window_seconds)

        if count > max_requests:
            raise APIProblemException(
                status_code=429,
                title="Rate Limit Exceeded",
                detail=f"Too many requests. Limit is {max_requests} request(s) per {window_seconds} seconds.",
                extra={"retry_after_seconds": window_seconds},
            )


rate_limiter = RateLimiter()


async def check_request_otp_rate_limit(request: Request, email: str = "") -> None:
    client_ip = request.client.host if request.client else "unknown"
    key = f"request_otp:{client_ip}:{email.lower()}"
    await rate_limiter.check_rate_limit(
        key=key,
        max_requests=settings.RATE_LIMIT_REQUEST_OTP_PER_MIN,
        window_seconds=60,
    )
