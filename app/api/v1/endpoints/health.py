from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.storage import storage_service

router = APIRouter()


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_status = "healthy"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    storage_status = "healthy"
    try:
        await storage_service.set("health_check_key", "ok", ttl_seconds=10)
        val = await storage_service.get("health_check_key")
        if val != "ok":
            storage_status = "unhealthy: Read mismatch"
    except Exception as e:
        storage_status = f"unhealthy: {str(e)}"

    is_healthy = db_status == "healthy" and storage_status == "healthy"

    return {
        "status": "ok" if is_healthy else "degraded",
        "database": db_status,
        "storage": storage_status,
    }
