from app.core.logging import RedactPIIProcessor


def test_redact_pii_processor():
    processor = RedactPIIProcessor()
    event_dict = {
        "event": "User logged in",
        "email": "john.doe@example.com",
        "phone_number": "+5215512345678",
        "password": "SuperSecretPassword123",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "otp": "654321",
        "nested": {
            "user_email": "jane.smith@domain.org",
            "safe_field": "public_data",
        },
    }

    result = processor(logger=None, method_name="info", event_dict=event_dict)

    assert result["email"] == "j***@example.com"
    assert result["phone_number"] == "+***REDACTED_PHONE***"
    assert result["password"] == "***REDACTED***"
    assert result["token"] == "***REDACTED***"
    assert result["otp"] == "***REDACTED***"
    assert result["nested"]["user_email"] == "j***@domain.org"
    assert result["nested"]["safe_field"] == "public_data"
