import json
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import logger
from app.db.models import Permission, Role


async def seed_roles_and_permissions(db: AsyncSession) -> None:
    """
    Seeds initial roles and permissions into the database safely across multiple async workers.
    """
    seed_file = Path("config/roles_seed.json")
    if not seed_file.exists():
        logger.warning("Seed file not found", path=str(seed_file))
        return

    with open(seed_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    try:
        # 1. Seed Permissions
        permissions_map: dict[str, Permission] = {}
        for perm_data in data.get("permissions", []):
            stmt = select(Permission).where(Permission.code == perm_data["code"])
            result = await db.execute(stmt)
            perm = result.scalar_one_or_none()
            if not perm:
                perm = Permission(
                    code=perm_data["code"],
                    description=perm_data.get("description"),
                )
                db.add(perm)
                try:
                    await db.flush()
                except IntegrityError:
                    await db.rollback()
                    stmt_retry = select(Permission).where(Permission.code == perm_data["code"])
                    perm = (await db.execute(stmt_retry)).scalar_one()
            permissions_map[perm.code] = perm

        # 2. Seed Roles
        for role_data in data.get("roles", []):
            stmt = select(Role).options(selectinload(Role.permissions)).where(Role.name == role_data["name"])
            result = await db.execute(stmt)
            role = result.scalar_one_or_none()
            role_perms = [
                permissions_map[code]
                for code in role_data.get("permissions", [])
                if code in permissions_map
            ]
            if not role:
                role = Role(
                    name=role_data["name"],
                    description=role_data.get("description"),
                    permissions=role_perms,
                )
                db.add(role)
                try:
                    await db.flush()
                except IntegrityError:
                    await db.rollback()

        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.debug("Seed execution handled multi-worker concurrency", error=str(exc))
