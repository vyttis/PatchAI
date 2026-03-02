"""Redis connection dependency with connection pool.

Production pool: max_connections=100, socket_keepalive=True.
Graceful fallback: if redis_url is empty, yield None.
"""

from typing import Optional

from redis.asyncio import ConnectionPool, Redis

from backend.app.config import settings

# Module-level connection pool — created once, reused across requests.
_pool: Optional[ConnectionPool] = None
if settings.redis_url:
    _pool = ConnectionPool.from_url(
        settings.redis_url,
        max_connections=100,
        socket_keepalive=True,
        decode_responses=True,
    )


def get_redis_pool() -> Optional[ConnectionPool]:
    """Return the module-level Redis connection pool (or None)."""
    return _pool


async def get_redis() -> Optional[Redis]:
    """Yield a Redis connection from the pool, or None if redis_url is not configured."""
    if not _pool:
        yield None
        return
    client = Redis(connection_pool=_pool)
    try:
        yield client
    finally:
        await client.aclose()
