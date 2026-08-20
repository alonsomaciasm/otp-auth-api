import csv
import io
import secrets
from typing import List

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import APIProblemException
from app.core.logging import logger
from app.core.security import hash_password
from app.db.models import Role, User
from app.db.session import get_db
from app.domain.otp_engine import record_dev_audit_event
from app.domain.rbac_engine import require_permissions
from app.schemas.users import AdminCreateUserRequest, RoleResponse, UserResponse

router = APIRouter()


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List Registered Users",
)
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_permissions(["admin:read"])),
):
    """
    Lists all registered users in system.
    Requires permission: admin:read.
    """
    stmt = (
        select(User)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .order_by(User.created_at.desc())
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Admin Single User Creation",
)
async def admin_create_user(
    body: AdminCreateUserRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_permissions(["admin:write"])),
):
    """
    Allows an administrator to create new user accounts directly.
    Requires permission: admin:write.
    """
    stmt = select(User).where(User.email == body.email.lower())
    res = await db.execute(stmt)
    if res.scalar_one_or_none():
        raise APIProblemException(
            status_code=400,
            title="Email Already Registered",
            detail="An account with this email address already exists.",
        )

    role_stmt = select(Role).where(Role.name == body.role_name)
    role_res = await db.execute(role_stmt)
    target_role = role_res.scalar_one_or_none()
    if not target_role:
        raise APIProblemException(
            status_code=400,
            title="Role Not Found",
            detail=f"Role '{body.role_name}' does not exist in system.",
        )

    hashed_pw = hash_password(body.password) if body.password else None

    new_user = User(
        email=body.email.lower(),
        phone_number=body.phone_number,
        hashed_password=hashed_pw,
        role_id=target_role.id,
        is_active=True,
        is_verified=body.is_verified,
    )
    db.add(new_user)
    await db.commit()

    stmt_created = (
        select(User)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.id == new_user.id)
    )
    res_created = await db.execute(stmt_created)
    created_user = res_created.scalar_one()

    logger.info("Admin created new user", created_user_id=created_user.id, admin_id=admin_user.id)
    await record_dev_audit_event(
        event_type="USER_CREATED",
        recipient=created_user.email,
        risk_level="info",
        actor=admin_user.email,
    )
    return created_user


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Admin Single User Deletion",
)
async def admin_delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_permissions(["admin:write"])),
):
    """
    Allows an administrator to delete an individual user by UUID.
    Requires permission: admin:write.
    """
    if str(admin_user.id) == str(user_id):
        raise APIProblemException(
            status_code=400,
            title="Self Deletion Prohibited",
            detail="Administrators cannot delete their own active account.",
        )

    stmt = select(User).where(User.id == user_id)
    res = await db.execute(stmt)
    target_user = res.scalar_one_or_none()

    if not target_user:
        raise APIProblemException(
            status_code=404,
            title="User Not Found",
            detail=f"User with ID '{user_id}' does not exist.",
        )

    user_email = target_user.email
    await db.delete(target_user)
    await db.commit()

    logger.info("Admin deleted user", deleted_user_id=user_id, deleted_email=user_email, admin_id=admin_user.id)
    await record_dev_audit_event(
        event_type="USER_DELETED",
        recipient=user_email,
        risk_level="warning",
        actor=admin_user.email,
    )

    return {
        "message": f"User '{user_email}' with ID '{user_id}' has been permanently deleted.",
        "deleted_user_id": user_id,
        "deleted_email": user_email,
    }


@router.post(
    "/users/upload-csv",
    status_code=status.HTTP_200_OK,
    summary="Bulk User Creation via CSV Upload",
)
async def upload_users_csv(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_permissions(["admin:write"])),
):
    """
    Allows an administrator to bulk populate users from a CSV file.
    Expected CSV Header Format:
    email,password,role,phone_number
    """
    if not file.filename or not file.filename.endswith(".csv"):
        raise APIProblemException(
            status_code=400,
            title="Invalid File Type",
            detail="File must be a valid .csv extension.",
        )

    content = await file.read()
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise APIProblemException(
            status_code=400,
            title="Encoding Error",
            detail="CSV file must be UTF-8 encoded.",
        )

    csv_reader = csv.DictReader(io.StringIO(decoded))

    roles_res = await db.execute(select(Role))
    roles_map = {r.name.lower(): r for r in roles_res.scalars().all()}

    total_processed = 0
    users_created = 0
    duplicates_skipped = 0
    errors = []

    for row_idx, row in enumerate(csv_reader, start=2):
        total_processed += 1
        email_raw = row.get("email", "").strip().lower()
        if not email_raw or "@" not in email_raw:
            errors.append(f"Line {row_idx}: Email inválido o ausente.")
            continue

        stmt_exist = select(User).where(User.email == email_raw)
        exist_res = await db.execute(stmt_exist)
        if exist_res.scalar_one_or_none():
            duplicates_skipped += 1
            continue

        password_raw = row.get("password", "").strip()
        role_name = row.get("role", "user").strip().lower()
        phone_number = row.get("phone_number", "").strip() or None

        target_role = roles_map.get(role_name) or roles_map.get("user")
        if not target_role:
            errors.append(f"Line {row_idx}: Rol '{role_name}' no existe.")
            continue

        hashed_pw = hash_password(password_raw) if password_raw else hash_password(secrets.token_urlsafe(12))

        new_user = User(
            email=email_raw,
            phone_number=phone_number,
            hashed_password=hashed_pw,
            role_id=target_role.id,
            is_active=True,
            is_verified=True,
        )
        db.add(new_user)
        users_created += 1

    await db.commit()
    logger.info(
        "Bulk CSV User Upload Completed",
        total_processed=total_processed,
        created=users_created,
        skipped=duplicates_skipped,
        admin_id=admin_user.id,
    )
    await record_dev_audit_event(
        event_type="CSV_BULK_UPLOAD",
        recipient=f"{users_created} usuarios creados",
        risk_level="info",
        actor=admin_user.email,
    )

    return {
        "message": "CSV user import completed successfully.",
        "total_processed": total_processed,
        "users_created": users_created,
        "duplicates_skipped": duplicates_skipped,
        "errors": errors,
    }


@router.get(
    "/roles",
    response_model=List[RoleResponse],
    summary="List Roles and Permissions",
)
async def list_roles(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_permissions(["admin:read"])),
):
    """
    Lists all system roles and their assigned permissions.
    Requires permission: admin:read.
    """
    stmt = select(Role).options(selectinload(Role.permissions))
    res = await db.execute(stmt)
    roles = res.scalars().all()
    return roles
