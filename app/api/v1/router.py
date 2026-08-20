from fastapi import APIRouter
from app.api.v1.endpoints import admin, auth, dashboard, health, pow, users, webauthn
from app.core import metrics

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(dashboard.router, tags=["Dashboard"])
api_router.include_router(metrics.router, tags=["Observability"])
api_router.include_router(pow.router, prefix="/auth", tags=["Proof-of-Work"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(webauthn.router, prefix="/auth", tags=["WebAuthn Passkeys"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])
