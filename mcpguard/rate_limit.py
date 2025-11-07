"""Token bucket rate limiting."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Dict

from .policy import RateLimitSettings

try:  # pragma: no cover - optional import
    from redis.asyncio import Redis
except Exception:  # pragma: no cover
    Redis = None  # type: ignore


TimeFunc = Callable[[], float]


@dataclass
class Bucket:
    tokens: float
    last_refill: float


class RateLimiter:
    """Token bucket rate limiter supporting memory and redis backends."""

    def __init__(
        self,
        settings: RateLimitSettings,
        *,
        time_func: TimeFunc | None = None,
        redis_client: "Redis | None" = None,
    ) -> None:
        self.settings = settings
        self._time = time_func or time.time
        self._buckets: Dict[str, Bucket] = {}
        self._lock = asyncio.Lock()
        self._redis = redis_client
        if self.settings.backend == "redis" and self._redis is None:
            if Redis is None:  # pragma: no cover - optional dependency
                raise RuntimeError("redis backend requested but redis package not installed")
            self._redis = Redis.from_url(settings.redis_dsn)  # type: ignore[call-arg]

    def _key(self, identity: str, tool: str) -> str:
        return f"mcpguard:bucket:{identity}:{tool}"

    async def _refill_memory(self, key: str, now: float) -> Bucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = Bucket(tokens=float(self.settings.capacity), last_refill=now)
            self._buckets[key] = bucket
            return bucket
        delta = now - bucket.last_refill
        refill = delta * self.settings.refill_rate_per_sec
        if refill > 0:
            bucket.tokens = min(self.settings.capacity, bucket.tokens + refill)
            bucket.last_refill = now
        return bucket

    async def consume(self, identity: str, tool: str, tokens: int = 1) -> bool:
        """Attempt to consume tokens for (identity, tool)."""

        if tokens <= 0:
            return True
        key = self._key(identity, tool)
        now = self._time()
        if self.settings.backend == "memory":
            async with self._lock:
                bucket = await self._refill_memory(key, now)
                if bucket.tokens >= tokens:
                    bucket.tokens -= tokens
                    return True
                return False
        else:
            if self._redis is None:  # pragma: no cover - safety
                raise RuntimeError("redis backend not configured")
            script = """
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local tokens = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])
            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local current_tokens = tonumber(bucket[1])
            local last_refill = tonumber(bucket[2])
            if not current_tokens then
                current_tokens = capacity
                last_refill = now
            end
            local delta = now - last_refill
            if delta > 0 then
                current_tokens = math.min(capacity, current_tokens + delta * refill_rate)
                last_refill = now
            end
            if current_tokens >= tokens then
                current_tokens = current_tokens - tokens
                redis.call('HMSET', key, 'tokens', current_tokens, 'last_refill', last_refill)
                redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) * 2)
                return {1, current_tokens}
            else
                redis.call('HMSET', key, 'tokens', current_tokens, 'last_refill', last_refill)
                redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) * 2)
                return {0, current_tokens}
            end
            """
            result = await self._redis.eval(  # type: ignore[operator]
                script,
                1,
                key,
                self.settings.capacity,
                self.settings.refill_rate_per_sec,
                tokens,
                now,
            )
            allowed = bool(result[0])
            return allowed

    async def get_remaining(self, identity: str, tool: str) -> int:
        key = self._key(identity, tool)
        now = self._time()
        if self.settings.backend == "memory":
            async with self._lock:
                bucket = await self._refill_memory(key, now)
                return int(bucket.tokens)
        if self._redis is None:  # pragma: no cover
            raise RuntimeError("redis backend not configured")
        data = await self._redis.hmget(key, "tokens", "last_refill")  # type: ignore[operator]
        tokens = data[0]
        if tokens is None:
            return self.settings.capacity
        return int(float(tokens))
