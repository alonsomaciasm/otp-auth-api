import logging
import re
import sys
from typing import Any, MutableMapping
import structlog


class RedactPIIProcessor:
    """
    Structlog processor that automatically redacts Sensitive PII data
    (emails, phone numbers, passwords, JWT tokens, OTPs) from logs.
    """

    EMAIL_REGEX = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
    PHONE_REGEX = re.compile(r"\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")
    SENSITIVE_KEYS = {
        "password",
        "hashed_password",
        "token",
        "access_token",
        "refresh_token",
        "otp",
        "code",
        "secret",
        "authorization",
    }

    def _redact_email(self, email: str) -> str:
        match = self.EMAIL_REGEX.search(email)
        if match:
            user, domain = match.groups()
            masked_user = user[0] + "***" if len(user) > 1 else "*"
            return f"{masked_user}@{domain}"
        return "[REDACTED_EMAIL]"

    def _redact_value(self, key: str, val: Any) -> Any:
        if isinstance(val, str):
            key_lower = key.lower()
            if key_lower in self.SENSITIVE_KEYS:
                return "***REDACTED***"
            if "email" in key_lower:
                return self._redact_email(val)
            if "phone" in key_lower:
                return "+***REDACTED_PHONE***"
            # Redact if raw value matches email format
            if self.EMAIL_REGEX.search(val):
                return self.EMAIL_REGEX.sub(r"\1[0]@***REDACTED_DOMAIN***", val)
        elif isinstance(val, dict):
            return {k: self._redact_value(k, v) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._redact_value(key, item) for item in val]
        return val

    def __call__(
        self, logger: structlog.types.WrappedLogger, method_name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        sanitized_dict: dict[str, Any] = {}
        for k, v in event_dict.items():
            sanitized_dict[k] = self._redact_value(k, v)
        return sanitized_dict


def setup_logging(environment: str = "development") -> None:
    log_level = logging.INFO

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=False),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        RedactPIIProcessor(),
    ]

    if environment == "development":
        renderer = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared_processors,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                renderer,
            ],
        )
    )

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)


logger = structlog.get_logger()
