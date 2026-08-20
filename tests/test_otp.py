import re
import pytest
from app.core.config import settings
from app.core.exceptions import APIProblemException
from app.core.security import generate_otp_code
from app.domain.otp_engine import OTPEngine
from app.services.storage import InMemoryStorage


@pytest.fixture(autouse=True)
def set_console_otp_channel(monkeypatch):
    monkeypatch.setattr(settings, "OTP_CHANNEL", "console")


@pytest.mark.asyncio
async def test_otp_generation_and_verification():
    storage = InMemoryStorage()
    engine = OTPEngine(storage=storage)
    target = "user@example.com"

    # Generate OTP
    await engine.generate_and_send(target)
    otp_code = await storage.get(engine._otp_key(target))
    assert otp_code is not None
    assert len(otp_code) == 6

    # Verify correct OTP
    verified = await engine.verify_otp(target, otp_code)
    assert verified is True

    # OTP should be single-use (deleted after verification)
    assert await storage.get(engine._otp_key(target)) is None


@pytest.mark.asyncio
async def test_otp_modes_character_sets():
    # Numeric mode
    code_num = generate_otp_code(8, otp_type="numeric")
    assert len(code_num) == 8
    assert re.match(r"^\d+$", code_num)

    # Alphanumeric Upper mode
    code_upper = generate_otp_code(8, otp_type="alphanumeric_upper")
    assert len(code_upper) == 8
    assert re.match(r"^[0-9A-Z]+$", code_upper)

    # Alphanumeric Full mode
    code_full = generate_otp_code(8, otp_type="alphanumeric_full")
    assert len(code_full) == 8
    assert re.match(r"^[0-9A-Za-z]+$", code_full)


@pytest.mark.asyncio
async def test_otp_failed_attempts_and_lockout():
    storage = InMemoryStorage()
    engine = OTPEngine(storage=storage)
    target = "lockout@example.com"

    await engine.generate_and_send(target)

    # Failed attempt 1
    with pytest.raises(APIProblemException) as exc_info:
        await engine.verify_otp(target, "000000")
    assert "2 attempt(s) remaining" in exc_info.value.detail

    # Failed attempt 2
    with pytest.raises(APIProblemException) as exc_info:
        await engine.verify_otp(target, "000000")
    assert "1 attempt(s) remaining" in exc_info.value.detail

    # Failed attempt 3 -> Lockout
    with pytest.raises(APIProblemException) as exc_info:
        await engine.verify_otp(target, "000000")
    assert exc_info.value.status_code == 429
    assert "Account Temporarily Locked Out" in exc_info.value.title

    # Verify target is locked out
    assert await engine.is_locked_out(target) is True
