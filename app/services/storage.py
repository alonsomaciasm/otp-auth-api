from abc import ABC, abstractmethod
import asyncio
import time
from typing import Dict, Optional, Tuple
import redis.asyncio as redis
from app.core.config import settings
from app.core.logging import logger


class BaseStorage(ABC):
    @abstractmethod
    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        pass

    @abstractmethod
    async def incr(self, key: str, ttl_seconds: Optional[int] = None) -> int:
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        pass


class InMemoryStorage(BaseStorage):
    """
    Isolated, thread-safe in-memory key-value store with TTL support
    for local development or environments without Redis.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Tuple[str, Optional[float]]] = {}
        self._lock = asyncio.Lock()

    def _is_expired(self, expiry: Optional[float]) -> bool:
        if expiry is None:
            return False
        return time.time() > expiry

    def _cleanup_key(self, key: str) -> None:
        if key in self._store:
            _, expiry = self._store[key]
            if self._is_expired(expiry):
                del self._store[key]

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        async with self._lock:
            expiry = (time.time() + ttl_seconds) if ttl_seconds else None
            self._store[key] = (value, expiry)

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            self._cleanup_key(key)
            if key not in self._store:
                return None
            value, _ = self._store[key]
            return value

    async def delete(self, key: str) -> bool:
        async with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    async def incr(self, key: str, ttl_seconds: Optional[int] = None) -> int:
        async with self._lock:
            self._cleanup_key(key)
            current_val = 0
            if key in self._store:
                val_str, _ = self._store[key]
                current_val = int(val_str)
            new_val = current_val + 1
            expiry = (time.time() + ttl_seconds) if ttl_seconds else None
            self._store[key] = (str(new_val), expiry)
            return new_val

    async def exists(self, key: str) -> bool:
        async with self._lock:
            self._cleanup_key(key)
            return key in self._store


class RedisStorage(BaseStorage):
    """
    Production-ready Redis storage implementation.
    """

    def __init__(self, redis_url: str) -> None:
        self.client = redis.from_url(redis_url, decode_responses=True)

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        if ttl_seconds:
            await self.client.set(key, value, ex=ttl_seconds)
        else:
            await self.client.set(key, value)

    async def get(self, key: str) -> Optional[str]:
        return await self.client.get(key)

    async def delete(self, key: str) -> bool:
        result = await self.client.delete(key)
        return result > 0

    async def incr(self, key: str, ttl_seconds: Optional[int] = None) -> int:
        val = await self.client.incr(key)
        if ttl_seconds and val == 1:
            await self.client.expire(key, ttl_seconds)
        return val

    async def exists(self, key: str) -> bool:
        return bool(await self.client.exists(key))


def get_storage_service() -> BaseStorage:
    if settings.USE_REDIS and settings.REDIS_URL:
        logger.info("Using Redis Storage", redis_url=settings.REDIS_URL)
        return RedisStorage(settings.REDIS_URL)
    logger.info("Using In-Memory Storage (Fallback)")
    return InMemoryStorage()


storage_service = get_storage_service()
