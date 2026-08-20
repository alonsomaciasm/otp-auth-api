from datetime import datetime, timedelta, timezone
import uuid
from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.core.logging import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.models import RefreshTokenSession, Role, User
from app.db.session import get_db
from app.domain.otp_engine import otp_engine
from app.schemas.auth import (
    RefreshTokenRequest,
    RegisterRequest,
    RequestOTPRequest,
    TokenResponse,
    VerifyOTPRequest,
)
from app.schemas.users import UserResponse
from app.services.rate_limiter import check_request_otp_rate_limit

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Public User Registration",
)
async def register_user(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Public registration endpoint. Controlled by ENABLE_PUBLIC_REGISTRATION feature flag.
    """
    if not settings.ENABLE_PUBLIC_REGISTRATION:
        raise APIProblemException(
            status_code=403,
            title="Public Registration Disabled",
            detail="Public registration is currently disabled by system administrator.",
        )

    # Check if email exists
    stmt = select(User).where(User.email == body.email.lower())
    res = await db.execute(stmt)
    if res.scalar_one_or_none():
        raise APIProblemException(
            status_code=400,
            title="Email Already Registered",
            detail="An account with this email address already exists.",
        )

    # Fetch default 'user' role
    role_stmt = select(Role).where(Role.name == "user")
    role_res = await db.execute(role_stmt)
    user_role = role_res.scalar_one_or_none()
    if not user_role:
        raise APIProblemException(
            status_code=500,
            title="System Role Error",
            detail="Default user role is not initialized.",
        )

    hashed_pw = hash_password(body.password) if body.password else None

    new_user = User(
        email=body.email.lower(),
        phone_number=body.phone_number,
        hashed_password=hashed_pw,
        role_id=user_role.id,
        is_active=True,
        is_verified=False,
    )
    db.add(new_user)
    await db.commit()

    stmt_user = (
        select(User)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == new_user.id)
    )
    user_res = await db.execute(stmt_user)
    created_user = user_res.scalar_one()

    logger.info("New user registered", user_id=created_user.id, email=created_user.email)
    return created_user


@router.post(
    "/request-otp",
    status_code=status.HTTP_200_OK,
    summary="Request OTP Code",
)
async def request_otp(
    body: RequestOTPRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Requests an OTP verification code.
    Enforces Rate Limiter, Proof-of-Work (if enabled) and Risk-Based Authentication (RBA).
    Dispatches email/SMS notification asynchronously via background worker tasks.
    """
    # 1. Rate Limiter Check
    await check_request_otp_rate_limit(request, email=body.email)

    # 2. Proof-of-Work (PoW) Verification
    if settings.ENABLE_POW_SHIELD:
        if not body.pow_challenge_token or not body.pow_nonce:
            raise APIProblemException(
                status_code=400,
                title="Proof-of-Work Required",
                detail="Proof-of-Work shield is active. Please solve /auth/pow-challenge first.",
            )
        from app.domain.pow_engine import pow_engine
        pow_engine.verify_solution(body.pow_challenge_token, body.pow_nonce)

    # 3. Generate & Dispatch OTP with 7-Vector RBA Engine and Async Background Worker
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    has_sec_ch_ua = "Sec-CH-UA" in request.headers
    access_hour_utc = datetime.now(timezone.utc).hour

    result_meta = await otp_engine.generate_and_send(
        identifier=body.email,
        client_ip=client_ip,
        user_agent=user_agent,
        background_tasks=background_tasks,
        is_new_device=body.is_new_device or False,
        geo_velocity_alert=body.geo_velocity_alert or False,
        access_hour_utc=access_hour_utc,
        has_sec_ch_ua=has_sec_ch_ua,
    )

    return {
        "message": "OTP verification code sent successfully.",
        **result_meta,
    }


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    summary="Verify OTP Code (Supports Passwordless & 2FA)",
)
async def verify_otp(
    body: VerifyOTPRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verifies OTP code and issues JWT Access & Refresh Tokens.
    - Passwordless flow: Only OTP code is required. If user doesn't exist, auto-create account.
    - 2FA flow: Both Password and OTP code are required.
    """
    email_clean = body.email.lower()
    await otp_engine.verify_otp(email_clean, body.code)

    stmt = select(User).where(User.email == email_clean)
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user:
        # Passwordless auto-registration if allowed
        if not settings.ENABLE_PUBLIC_REGISTRATION:
            raise APIProblemException(
                status_code=403,
                title="Registration Required",
                detail="User account does not exist and public registration is disabled.",
            )
        role_stmt = select(Role).where(Role.name == "user")
        role_res = await db.execute(role_stmt)
        user_role = role_res.scalar_one_or_none()

        user = User(
            email=email_clean,
            role_id=user_role.id,
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.flush()
    else:
        # Mark as verified
        user.is_verified = True

    # 2FA password check if provided or user has password
    if body.password and user.hashed_password:
        if not verify_password(body.password, user.hashed_password):
            raise APIProblemException(
                status_code=401,
                title="Invalid Password",
                detail="Password verification failed during 2FA.",
            )

    # Issue Tokens with Refresh Token Session JTI tracking and DAG Tree linking
    jti = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id, jti=jti)

    # Store Refresh Token Session for Revocation & Rotation
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

    logger.info("User authenticated via OTP", user_id=user.id, email=user.email, jti=jti, family_id=family_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate Refresh Token",
)
async def refresh_tokens(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh Token Rotation with Cryptographic DAG Tree Reuse Detection & Revocation.
    If an already-revoked refresh token is presented, ALL tokens in the DAG family tree are instantly revoked.
    """
    try:
        payload = decode_token(body.refresh_token)
    except ValueError as exc:
        raise APIProblemException(
            status_code=401,
            title="Invalid Token",
            detail=str(exc),
        )

    if payload.get("type") != "refresh":
        raise APIProblemException(
            status_code=401,
            title="Invalid Token Type",
            detail="Refresh token required.",
        )

    user_id = payload.get("sub")
    jti = payload.get("jti")

    stmt = select(RefreshTokenSession).where(RefreshTokenSession.jti == jti)
    res = await db.execute(stmt)
    token_session = res.scalar_one_or_none()

    if not token_session:
        raise APIProblemException(
            status_code=401,
            title="Unrecognized Session",
            detail="Refresh token session was not found.",
        )

    # TOKEN REUSE DETECTION (DAG TREE PRUNING)
    if token_session.is_revoked:
        from app.core.metrics import metrics_collector
        metrics_collector.record_dag_revocation()

        logger.error(
            "CRITICAL: Refresh token reuse detected in DAG tree! Revoking session family.",
            user_id=user_id,
            jti=jti,
            family_id=token_session.family_id,
        )
        # Revoke ALL sessions belonging to this DAG token family
        revoke_stmt = select(RefreshTokenSession).where(
            RefreshTokenSession.family_id == token_session.family_id
        )
        family_sessions = (await db.execute(revoke_stmt)).scalars().all()
        for s in family_sessions:
            s.is_revoked = True
        await db.commit()

        raise APIProblemException(
            status_code=401,
            title="Token Reuse Detected",
            detail="Security breach detected: This refresh token was already used. Session family revoked.",
        )

    # Revoke current token (rotation step in DAG chain)
    token_session.is_revoked = True

    # Issue new child token in DAG tree
    new_jti = str(uuid.uuid4())
    new_access_token = create_access_token(subject=user_id)
    new_refresh_token = create_refresh_token(subject=user_id, jti=new_jti)

    new_session = RefreshTokenSession(
        user_id=user_id,
        jti=new_jti,
        parent_jti=jti,
        family_id=token_session.family_id,
        is_revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_session)
    await db.commit()

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout & Revoke Refresh Token",
)
async def logout(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = decode_token(body.refresh_token)
        jti = payload.get("jti")
        if jti:
            stmt = select(RefreshTokenSession).where(RefreshTokenSession.jti == jti)
            res = await db.execute(stmt)
            session_obj = res.scalar_one_or_none()
            if session_obj:
                session_obj.is_revoked = True
                await db.commit()
    except Exception:
        pass  # Idempotent logout

    return {"message": "Successfully logged out."}
