from fastapi import APIRouter, status
from app.core.config import settings
from app.domain.pow_engine import pow_engine

router = APIRouter()


@router.get(
    "/pow-challenge",
    status_code=status.HTTP_200_OK,
    summary="Get Proof-of-Work Challenge",
)
async def get_pow_challenge():
    """
    Returns a cryptographic PoW challenge token and difficulty level for client-side solving.
    """
    from app.core.metrics import metrics_collector
    metrics_collector.record_pow_issued()
    challenge_id, challenge_token, difficulty = pow_engine.generate_challenge()
    return {
        "challenge_id": challenge_id,
        "challenge_token": challenge_token,
        "difficulty_bits": difficulty,
        "algorithm": "SHA-256",
        "instruction": f"Find nonce 'n' such that SHA256(challenge_id + ':' + n) starts with {difficulty // 4} hex zeros.",
    }
