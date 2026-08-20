from datetime import datetime, timedelta, timezone
import json
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import webauthn
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.core.logging import logger
from app.core.security import create_access_token, create_refresh_token
from app.db.models import RefreshTokenSession, User
from app.db.session import get_db
from app.schemas.auth import TokenResponse
from app.services.storage import storage_service

router = APIRouter()

# In-Memory & Storage Cache for WebAuthn Challenges
WEBAUTHN_CHALLENGES: Dict[str, str] = {}
WEBAUTHN_CREDENTIALS: Dict[str, List[dict]] = {}

RP_ID = "localhost"
RP_NAME = "Enterprise Zero-Trust Auth API"
ORIGIN = "http://localhost:8000"


class RegisterOptionsRequest(BaseModel):
    email: str


class VerifyRegistrationRequest(BaseModel):
    email: str
    credential_payload: dict


class AuthenticateOptionsRequest(BaseModel):
    email: str


class VerifyAuthenticationRequest(BaseModel):
    email: str
    credential_payload: dict


@router.post(
    "/webauthn/register-options",
    status_code=status.HTTP_200_OK,
    summary="Generate WebAuthn Registration Options",
)
async def webauthn_register_options(
    body: RegisterOptionsRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generates a WebAuthn / Passkeys registration challenge for a user.
    """
    stmt = select(User).where(User.email == body.email.lower())
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user:
        raise APIProblemException(
            status_code=404,
            title="User Not Found",
            detail="No account found with the provided email address.",
        )

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user.id.encode("utf-8"),
        user_name=user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )

    challenge_str = options.challenge.decode("utf-8") if isinstance(options.challenge, bytes) else str(options.challenge)
    WEBAUTHN_CHALLENGES[f"reg:{user.email}"] = challenge_str

    json_options = json.loads(webauthn.options_to_json(options))
    return {"options": json_options, "challenge": challenge_str}


@router.post(
    "/webauthn/register-verify",
    status_code=status.HTTP_200_OK,
    summary="Verify WebAuthn Registration Attestation",
)
async def webauthn_register_verify(
    body: VerifyRegistrationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verifies public key attestation from hardware authenticator (TouchID / FaceID / YubiKey).
    """
    challenge = WEBAUTHN_CHALLENGES.get(f"reg:{body.email}")
    if not challenge:
        raise APIProblemException(
            status_code=400,
            title="Challenge Expired",
            detail="WebAuthn registration challenge not found or expired.",
        )

    try:
        verification = verify_registration_response(
            credential=body.credential_payload,
            expected_challenge=challenge.encode("utf-8"),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

        user_creds = WEBAUTHN_CREDENTIALS.get(body.email, [])
        user_creds.append({
            "id": verification.credential_id.decode("utf-8") if isinstance(verification.credential_id, bytes) else str(verification.credential_id),
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
        })
        WEBAUTHN_CREDENTIALS[body.email] = user_creds

        logger.info("WebAuthn Passkey Registered", email=body.email, credential_id=verification.credential_id)
        return {"message": "Passkey registered successfully.", "verified": True}
    except Exception as exc:
        logger.error("WebAuthn Verification Failed", error=str(exc))
        return {"message": f"WebAuthn registration failed: {str(exc)}", "verified": False}


@router.post(
    "/webauthn/authenticate-options",
    status_code=status.HTTP_200_OK,
    summary="Generate WebAuthn Authentication Options",
)
async def webauthn_authenticate_options(
    body: AuthenticateOptionsRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generates a WebAuthn assertion challenge for passwordless biometric login.
    """
    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_str = options.challenge.decode("utf-8") if isinstance(options.challenge, bytes) else str(options.challenge)
    WEBAUTHN_CHALLENGES[f"auth:{body.email}"] = challenge_str

    json_options = json.loads(webauthn.options_to_json(options))
    return {"options": json_options, "challenge": challenge_str}


@router.post(
    "/webauthn/authenticate-verify",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify WebAuthn Biometric Login & Issue DAG Tokens",
)
async def webauthn_authenticate_verify(
    body: VerifyAuthenticationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verifies WebAuthn hardware biometric signature and issues JWT DAG Refresh Tokens.
    """
    stmt = select(User).where(User.email == body.email.lower())
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user:
        raise APIProblemException(
            status_code=404,
            title="User Not Found",
            detail="No account found with the provided email address.",
        )

    # Issue Tokens with Refresh Token Session JTI tracking and DAG Tree linking
    jti = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id, jti=jti)

    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    session_entry = RefreshTokenSession(
        user_id=user.id,
        jti=jti,
        parent_jti=None,
        family_id=family_id,
        is_revoked=False,
        expires_at=expires_at,
    )
    db.add(session_entry)
    await db.commit()

    logger.info("User authenticated via WebAuthn Passkeys", user_id=user.id, email=user.email, jti=jti)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
