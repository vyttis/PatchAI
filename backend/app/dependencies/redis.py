"""Redis connection dependency."""

from typing import Optional

from redis.asyncio import Redis

from backend.app.config import settings


async def get_redis() -> Optional[Redis]:
    """Yield a Redis connection, or None if redis_url is not configured."""
    if not settings.redis_url:
        yield None
        return
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()
