from typing import Literal, Optional
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    # General
    PROJECT_NAME: str = "Enterprise OTP Auth API"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # Feature Flags
    ENABLE_PUBLIC_REGISTRATION: bool = True
    ENABLE_POW_SHIELD: bool = True
    ENABLE_RISK_BASED_OTP: bool = True
    ENABLE_DAG_TOKEN_ROTATION: bool = True

    # Proof of Work (PoW) Config
    POW_DIFFICULTY_BITS: int = 12  # 12 bits zeros (~30-100ms client-side)

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./sql_app.db"  # Supports postgresql+asyncpg:// or sqlite+aiosqlite:///

    # Storage & Redis
    USE_REDIS: bool = False
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"

    # Security & Tokens
    JWT_SECRET_KEY: SecretStr = Field(default="SUPER_SECRET_CHANGE_ME_IN_PRODUCTION_KEY_32BYTES_MIN!")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # OTP Config
    OTP_EXPIRE_SECONDS: int = 300  # 5 minutes
    OTP_MAX_ATTEMPTS: int = 3
    OTP_LOCKOUT_SECONDS: int = 900  # 15 minutes lockout after max failed attempts
    OTP_CHANNEL: Literal["console", "smtp"] = "console"
    OTP_TYPE: Literal["numeric", "alphanumeric_upper", "alphanumeric_full"] = "numeric"
    OTP_LENGTH: int = 6

    # Rate Limiting & Security Payload Limits
    RATE_LIMIT_REQUEST_OTP_PER_MIN: int = 3
    MAX_PAYLOAD_SIZE_MB: int = 2          # 2 MB max for standard JSON requests
    MAX_FILE_UPLOAD_SIZE_MB: int = 10      # 10 MB max for file uploads (CSV, etc.)

    # Configurable High-Performance JSON Parser Engine (msgspec vs pydantic)
    JSON_PARSER_ENGINE: Literal["pydantic", "msgspec"] = "msgspec"

    # SMTP Configuration (Optional if OTP_CHANNEL=smtp)
    SMTP_HOST: Optional[str] = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    SMTP_FROM_EMAIL: Optional[str] = None
    SMTP_TLS: bool = True

    # Customizable Email Template Settings
    EMAIL_SUBJECT_PREFIX: str = "Código de Verificación"
    EMAIL_BRAND_NAME: str = "Autenticación de Seguridad"
    EMAIL_BRAND_SLOGAN: str = "Zero-Trust Multi-Factor Authentication"
    EMAIL_GREETING: str = "Hola,"
    EMAIL_BODY_TEXT: str = "Usa el siguiente código de verificación de un solo uso para completar tu inicio de sesión:"
    EMAIL_SECURITY_NOTICE: str = "🔒 Aviso de Seguridad: Si no intentaste iniciar sesión, ignora este mensaje. Nunca compartas este código con nadie; nuestro personal jamás te lo solicitará."
    EMAIL_FOOTER_TEXT: str = "Este mensaje fue generado automáticamente. © 2026 Enterprise Zero-Trust Security Architecture."


settings = Settings()
