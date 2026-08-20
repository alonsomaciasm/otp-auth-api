import json
from typing import Callable, List, Optional
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.orm import selectinload

from app.core.exceptions import APIProblemException
from app.core.security import decode_token
from app.db.models import Role, User
from app.db.session import get_db
from app.services.storage import storage_service

security_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise APIProblemException(
            status_code=401,
            title="Missing Authentication Credentials",
            detail="Authorization bearer token is required.",
        )

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise APIProblemException(
            status_code=401,
            title="Invalid Authentication Token",
            detail=str(exc),
        )

    if payload.get("type") != "access":
        raise APIProblemException(
            status_code=401,
            title="Invalid Token Type",
            detail="Access token expected.",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise APIProblemException(
            status_code=401,
            title="Invalid Token Payload",
            detail="User subject missing from token.",
        )

    stmt = select(User).options(selectinload(User.role).selectinload(Role.permissions)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise APIProblemException(
            status_code=401,
            title="User Not Found",
            detail="The user associated with this token no longer exists.",
        )

    if not user.is_active:
        raise APIProblemException(
            status_code=403,
            title="Account Disabled",
            detail="User account is deactivated.",
        )

    return user


async def get_user_permissions(user: User) -> list[str]:
    """
    Fetches user permissions with caching in storage_service.
    """
    cache_key = f"rbac:permissions:role:{user.role_id}"
    cached_perms = await storage_service.get(cache_key)
    if cached_perms:
        return json.loads(cached_perms)

    permissions = [perm.code for perm in user.role.permissions]
    await storage_service.set(cache_key, json.dumps(permissions), ttl_seconds=3600)
    return permissions


def require_permissions(required_permissions: List[str]) -> Callable:
    """
    FastAPI dependency factory enforcing RBAC permission checks.
    Evaluates whether the authenticated user possesses all required permissions.
    """

    async def permission_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_perms = await get_user_permissions(current_user)
        user_perm_set = set(user_perms)

        missing_perms = [p for p in required_permissions if p not in user_perm_set]

        if missing_perms:
            raise APIProblemException(
                status_code=403,
                title="Forbidden: Insufficient Permissions",
                detail=f"Access denied. Missing required permission(s): {', '.join(missing_perms)}.",
                extra={"required_permissions": required_permissions, "missing_permissions": missing_perms},
            )

        return current_user

    return permission_dependency
