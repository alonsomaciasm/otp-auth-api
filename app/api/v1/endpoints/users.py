from fastapi import APIRouter, Depends
from app.db.models import User
from app.domain.rbac_engine import require_permissions
from app.schemas.users import UserResponse

router = APIRouter()


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
)
async def get_my_profile(
    current_user: User = Depends(require_permissions(["users:read"])),
):
    """
    Returns profile information of the currently authenticated user.
    Requires permission: users:read.
    """
    return current_user
