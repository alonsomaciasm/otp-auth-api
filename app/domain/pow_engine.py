from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from typing import Tuple
import jwt
from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.core.logging import logger


class POWEngine:
    """
    Cryptographic Proof-of-Work (PoW) engine for front-door anti-bot protection.
    """

    def generate_challenge(self, difficulty_bits: int = settings.POW_DIFFICULTY_BITS) -> tuple[str, str, int]:
        """
        Generates a cryptographic PoW challenge token signed with JWT.
        Returns: (challenge_id, signed_token, difficulty_bits)
        """
        challenge_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=5)

        payload = {
            "challenge_id": challenge_id,
            "difficulty_bits": difficulty_bits,
            "exp": expires_at,
            "type": "pow_challenge",
        }

        signed_token = jwt.encode(
            payload,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithm=settings.JWT_ALGORITHM,
        )
        return challenge_id, signed_token, difficulty_bits

    def verify_solution(self, challenge_token: str, nonce: str) -> bool:
        """
        Verifies client PoW solution:
        Validates SHA256(challenge_id + ":" + nonce) has d leading zero bits.
        Takes <0.1ms on server.
        """
        try:
            payload = jwt.decode(
                challenge_token,
                settings.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
            )
        except jwt.PyJWTError as exc:
            raise APIProblemException(
                status_code=400,
                title="Invalid PoW Challenge Token",
                detail=f"Challenge verification failed: {str(exc)}",
            )

        if payload.get("type") != "pow_challenge":
            raise APIProblemException(
                status_code=400,
                title="Invalid Challenge Type",
                detail="Token is not a valid PoW challenge.",
            )

        challenge_id = payload["challenge_id"]
        difficulty_bits = payload.get("difficulty_bits", settings.POW_DIFFICULTY_BITS)

        # Hash computation
        data = f"{challenge_id}:{nonce.strip()}".encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()

        target_hex_zeros = difficulty_bits // 4
        target_prefix = "0" * target_hex_zeros

        from app.core.metrics import metrics_collector
        if not digest.startswith(target_prefix):
            metrics_collector.record_pow_failed()
            logger.warning(
                "Invalid PoW solution provided",
                challenge_id=challenge_id,
                digest=digest,
                required_prefix=target_prefix,
            )
            raise APIProblemException(
                status_code=400,
                title="Proof-of-Work Verification Failed",
                detail=f"Nonce failed SHA-256 challenge difficulty ({difficulty_bits} bits).",
            )

        metrics_collector.record_pow_verified()
        logger.info("PoW solution verified successfully", challenge_id=challenge_id)
        return True


pow_engine = POWEngine()
