from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    phone_number: Optional[str] = Field(None, json_schema_extra={"example": "+1234567890"})
    password: Optional[str] = Field(None, min_length=8, json_schema_extra={"example": "SecretP@ss123"})


class RequestOTPRequest(BaseModel):
    email: EmailStr
    pow_challenge_token: Optional[str] = Field(None, description="Signed PoW challenge token if POW_SHIELD is enabled")
    pow_nonce: Optional[str] = Field(None, description="Solved PoW nonce string")
    is_new_device: Optional[bool] = Field(False, description="Flag indicating unrecognized new device footprint")
    geo_velocity_alert: Optional[bool] = Field(False, description="Flag indicating impossible geo-velocity travel anomaly")


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=12, json_schema_extra={"example": "123456"})
    password: Optional[str] = Field(None, description="Provided if doing Password + OTP (2FA)")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str
