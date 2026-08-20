import pytest


@pytest.mark.asyncio
async def test_request_otp_rate_limiter_exceeded(client, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "ENABLE_POW_SHIELD", False)
    email = "ratelimit@example.com"

    # Calls 1, 2, 3 should succeed
    for i in range(3):
        res = await client.post(
            "/api/v1/auth/request-otp",
            json={"email": email},
        )
        assert res.status_code == 200

    # Call 4 should fail with 429 Too Many Requests RFC 7807
    res_exceeded = await client.post(
        "/api/v1/auth/request-otp",
        json={"email": email},
    )
    assert res_exceeded.status_code == 429
    assert res_exceeded.headers.get("content-type") == "application/problem+json"
    data = res_exceeded.json()
    assert data["title"] == "Rate Limit Exceeded"
