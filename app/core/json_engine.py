import json
from typing import Any, Dict, TypeVar
import msgspec
from app.core.config import settings
from app.core.logging import logger

T = TypeVar("T")


class JSONEngine:
    """
    High-Performance Configurable JSON Parser Engine.
    Supports dynamic switching via settings.JSON_PARSER_ENGINE ("msgspec" vs "pydantic"/stdlib json).
    Allows sub-millisecond serialization and parsing under high concurrency workloads.
    """

    def __init__(self, engine_name: str | None = None):
        self.engine_name = (engine_name or settings.JSON_PARSER_ENGINE).lower()
        logger.info("Initialized JSON Parser Engine", engine=self.engine_name)

    def encode(self, obj: Any) -> str:
        """Encodes Python data structure into JSON string."""
        if self.engine_name == "msgspec":
            return msgspec.json.encode(obj).decode("utf-8")
        else:
            return json.dumps(obj)

    def decode(self, payload: str | bytes) -> Dict[str, Any]:
        """Decodes JSON payload string or bytes into Python dictionary."""
        if self.engine_name == "msgspec":
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            return msgspec.json.decode(payload)
        else:
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8")
            return json.loads(payload)


json_engine = JSONEngine()
