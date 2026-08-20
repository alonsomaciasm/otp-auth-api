from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr


class PermissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    code: str
    description: Optional[str] = None


class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    permissions: List[PermissionResponse] = []


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    phone_number: Optional[str] = None
    role: RoleResponse
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    phone_number: Optional[str] = None
    password: Optional[str] = None
    role_name: str = "user"
    is_verified: bool = True
