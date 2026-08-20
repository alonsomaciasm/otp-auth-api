import pytest
from app.core.config import settings
from app.services.storage import InMemoryStorage


@pytest.mark.asyncio
async def test_public_registration_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_PUBLIC_REGISTRATION", False)
    res = await client.post(
        "/api/v1/auth/register",
        json={"email": "disabled@example.com", "password": "password123"},
    )
    assert res.status_code == 403
    assert res.headers.get("content-type") == "application/problem+json"
    data = res.json()
    assert data["title"] == "Public Registration Disabled"


@pytest.mark.asyncio
async def test_full_auth_and_token_rotation_flow(client, db_session):
    # 1. Register User
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"email": "flow@example.com", "password": "SecurePassword123!"},
    )
    assert reg_res.status_code == 201

    # 2. Get and Solve PoW Challenge
    pow_res = await client.get("/api/v1/auth/pow-challenge")
    pow_data = pow_res.json()
    from app.domain.pow_engine import pow_engine
    import hashlib
    nonce = 0
    target_prefix = "0" * (pow_data["difficulty_bits"] // 4)
    while True:
        if hashlib.sha256(f"{pow_data['challenge_id']}:{nonce}".encode("utf-8")).hexdigest().startswith(target_prefix):
            break
        nonce += 1

    otp_req = await client.post(
        "/api/v1/auth/request-otp",
        json={
            "email": "flow@example.com",
            "pow_challenge_token": pow_data["challenge_token"],
            "pow_nonce": str(nonce),
        },
    )
    assert otp_req.status_code == 200

    # Retrieve code from storage engine
    from app.domain.otp_engine import otp_engine
    otp_code = await otp_engine.storage.get(otp_engine._otp_key("flow@example.com"))

    # 3. Verify OTP
    ver_res = await client.post(
        "/api/v1/auth/verify-otp",
        json={
            "email": "flow@example.com",
            "code": otp_code,
            "password": "SecurePassword123!",
        },
    )
    assert ver_res.status_code == 200
    tokens = ver_res.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 4. Access Protected Profile Route
    me_res = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "flow@example.com"

    # 5. Rotate Refresh Token
    rot_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert rot_res.status_code == 200
    new_tokens = rot_res.json()
    new_refresh_token = new_tokens["refresh_token"]

    # 6. REUSE DETECTED: Attempting to use old refresh_token again triggers revocation!
    reuse_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert reuse_res.status_code == 401
    assert "Token Reuse Detected" in reuse_res.json()["title"]

    # 7. Verification that new_refresh_token is also revoked due to breach protocol
    breach_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert breach_res.status_code == 401
