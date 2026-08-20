from datetime import datetime, timezone
import json
from typing import Any, Optional, Tuple

from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.core.logging import logger
from app.core.security import generate_otp_code
from app.services.otp.smtp import get_otp_channel_strategy
from app.services.storage import BaseStorage, storage_service

DEV_AUDIT_EVENTS: list[dict] = []


async def record_dev_audit_event(
    event_type: str,
    recipient: str,
    code: Optional[str] = None,
    risk_level: Optional[str] = None,
    risk_score: Optional[float] = None,
    risk_factors: Optional[list] = None,
    actor: Optional[str] = "SYSTEM",
):
    """
    Records security audit log events with actor attribution (admin email or SYSTEM).
    """
    event = {
        "timestamp": datetime.now().astimezone().strftime("%H:%M:%S"),
        "event_type": event_type,
        "recipient": recipient,
        "actor": actor or "SYSTEM",
        "code": code if code else "***REDACTED***",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors or [],
    }
    DEV_AUDIT_EVENTS.insert(0, event)
    if len(DEV_AUDIT_EVENTS) > 50:
        DEV_AUDIT_EVENTS.pop()

    try:
        current_raw = await storage_service.get("dev:audit_events")
        current_list = json.loads(current_raw) if current_raw else []
        current_list.insert(0, event)
        await storage_service.set("dev:audit_events", json.dumps(current_list[:50]), ttl_seconds=3600)
    except Exception:
        pass


class OTPEngine:
    def __init__(self, storage: BaseStorage = storage_service):
        self.storage = storage
        self.channel_strategy = get_otp_channel_strategy()

    def _otp_key(self, identifier: str) -> str:
        return f"otp:code:{identifier.lower()}"

    def _attempts_key(self, identifier: str) -> str:
        return f"otp:attempts:{identifier.lower()}"

    def _lockout_key(self, identifier: str) -> str:
        return f"otp:lockout:{identifier.lower()}"

    async def generate_and_send(
        self,
        identifier: str,
        client_ip: str = "unknown",
        user_agent: str = "unknown",
        background_tasks: Optional[Any] = None,
        is_new_device: bool = False,
        geo_velocity_alert: bool = False,
        access_hour_utc: Optional[int] = None,
        has_sec_ch_ua: bool = True,
    ) -> dict:
        """
        Generates an OTP based on 8-vector RBA risk evaluation (including ML Isolation Forest),
        stores it with TTL, and dispatches it asynchronously.
        """
        clean_identifier = identifier.strip().lower()

        if await self.is_locked_out(clean_identifier):
            raise APIProblemException(
                status_code=429,
                title="Account Temporarily Locked Out",
                detail=f"Too many failed OTP attempts. Account is locked out for {settings.OTP_LOCKOUT_SECONDS // 60} minutes.",
            )

        failed_attempts_str = await self.storage.get(self._attempts_key(clean_identifier))
        failed_attempts_count = int(failed_attempts_str) if failed_attempts_str else 0

        from app.domain.risk_engine import risk_engine

        policy = risk_engine.get_otp_policy(
            client_ip=client_ip,
            user_agent=user_agent,
            is_new_device=is_new_device,
            geo_velocity_alert=geo_velocity_alert,
            failed_attempts_count=failed_attempts_count,
            access_hour_utc=access_hour_utc,
            has_sec_ch_ua=has_sec_ch_ua,
        )
        code = generate_otp_code(length=policy.length, otp_type=policy.otp_type)

        await self.storage.set(
            self._otp_key(clean_identifier),
            code,
            ttl_seconds=policy.ttl_seconds,
        )

        await self.storage.delete(self._attempts_key(clean_identifier))

        if background_tasks:
            async def _async_send():
                await self.channel_strategy.send_otp(clean_identifier, code)
            background_tasks.add_task(_async_send)
        else:
            success = await self.channel_strategy.send_otp(clean_identifier, code)
            if not success:
                raise APIProblemException(
                    status_code=500,
                    title="OTP Delivery Failed",
                    detail="Failed to send verification code. Please try again later.",
                )

        logger.info(
            "OTP generated and sent",
            recipient=clean_identifier,
            otp_length=policy.length,
            otp_type=policy.otp_type,
            risk_level=policy.risk_level,
            risk_score=policy.risk_score,
            entropy_bits=policy.entropy_bits,
            risk_factors=policy.risk_factors,
            channel=settings.OTP_CHANNEL,
        )

        await record_dev_audit_event(
            event_type="OTP_GENERATED",
            recipient=clean_identifier,
            code=code,
            risk_level=policy.risk_level,
            risk_score=policy.risk_score,
            risk_factors=policy.risk_factors,
            actor="SYSTEM",
        )

        return {
            "message": f"Verification code sent to {clean_identifier}",
            "expires_in_seconds": policy.ttl_seconds,
            "risk_level": policy.risk_level,
            "risk_score": policy.risk_score,
            "risk_factors": policy.risk_factors,
            "entropy_bits": policy.entropy_bits,
            "otp_length": policy.length,
            "otp_type": policy.otp_type,
            "dev_otp_code": code if settings.ENVIRONMENT == "development" else None,
        }

    async def verify_otp(self, identifier: str, code: str) -> bool:
        """
        Verifies the provided OTP code against storage. Increments lockout counter on failure.
        """
        clean_identifier = identifier.strip().lower()

        if await self.is_locked_out(clean_identifier):
            raise APIProblemException(
                status_code=429,
                title="Account Temporarily Locked Out",
                detail=f"Too many failed OTP attempts. Account is locked out for {settings.OTP_LOCKOUT_SECONDS // 60} minutes.",
            )

        stored_code = await self.storage.get(self._otp_key(clean_identifier))

        if not stored_code or stored_code != code.strip():
            attempts = await self.storage.incr(self._attempts_key(clean_identifier), ttl_seconds=settings.OTP_LOCKOUT_SECONDS)
            remaining = settings.OTP_MAX_ATTEMPTS - attempts

            if attempts >= settings.OTP_MAX_ATTEMPTS:
                await self.storage.set(
                    self._lockout_key(clean_identifier),
                    "locked",
                    ttl_seconds=settings.OTP_LOCKOUT_SECONDS,
                )
                logger.warning("Account locked out due to max failed OTP attempts", recipient=clean_identifier)
                await record_dev_audit_event(
                    event_type="ACCOUNT_LOCKED_OUT",
                    recipient=clean_identifier,
                    risk_level="high",
                    actor="SYSTEM",
                )
                raise APIProblemException(
                    status_code=429,
                    title="Account Temporarily Locked Out",
                    detail=f"Too many failed attempts. Account locked out for {settings.OTP_LOCKOUT_SECONDS // 60} minutes.",
                )

            logger.warning("Invalid OTP verification attempt", recipient=clean_identifier, attempts=attempts, remaining=remaining)
            await record_dev_audit_event(
                event_type="OTP_VERIFY_FAILED",
                recipient=clean_identifier,
                risk_level="warning",
                actor="SYSTEM",
            )
            raise APIProblemException(
                status_code=400,
                title="Invalid Verification Code",
                detail=f"Invalid OTP code. {remaining} attempt(s) remaining before account lockout.",
            )

        await self.storage.delete(self._otp_key(clean_identifier))
        await self.storage.delete(self._attempts_key(clean_identifier))

        logger.info("OTP verification successful", recipient=clean_identifier)
        await record_dev_audit_event(
            event_type="OTP_VERIFIED",
            recipient=clean_identifier,
            risk_level="low",
            actor="SYSTEM",
        )
        return True

    async def is_locked_out(self, identifier: str) -> bool:
        clean_identifier = identifier.strip().lower()
        lockout_flag = await self.storage.get(self._lockout_key(clean_identifier))
        return lockout_flag is not None


otp_engine = OTPEngine()
