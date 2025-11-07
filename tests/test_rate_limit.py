import pytest

from mcpguard.policy import RateLimitSettings
from mcpguard.rate_limit import RateLimiter


class FakeTime:
    def __init__(self) -> None:
        self._now = 0.0

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def time(self) -> float:
        return self._now


@pytest.mark.asyncio
async def test_rate_limiter_memory() -> None:
    settings = RateLimitSettings(capacity=2, refill_rate_per_sec=1.0, backend="memory")
    clock = FakeTime()
    limiter = RateLimiter(settings, time_func=clock.time)

    assert await limiter.consume("alice", "calculator.add")
    assert await limiter.consume("alice", "calculator.add")
    assert not await limiter.consume("alice", "calculator.add")
    remaining = await limiter.get_remaining("alice", "calculator.add")
    assert remaining == 0
    clock.advance(2.0)
    assert await limiter.consume("alice", "calculator.add")
