"""Redis sliding-window rate limiter — ASGI middleware.

Two tiers:
- Device routes (/api/v1/devices/): rate_limit_device_rpm per device (x-device-cert-cn)
- Org API routes (/api/v1/orgs/): rate_limit_org_rpm per org (org_id from URL)

Graceful fallback: if Redis unavailable, ALLOW request (never block on Redis failure).
Skip: /health, /docs, WebSocket, /api/v1/auth/, /api/v1/enrollment/, next-command (BLPOP).
"""

import logging
import re
import time
from typing import Optional

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

_ORG_ID_RE = re.compile(r"/api/v1/orgs/([0-9a-f-]{36})/")

# Paths to skip rate limiting entirely
_SKIP_PREFIXES = ("/health", "/docs", "/openapi.json", "/api/v1/auth/", "/api/v1/enrollment/")
_SKIP_CONTAINS = ("/next-command",)


class RateLimiter:
    """ASGI middleware implementing Redis sliding-window rate limiting."""

    def __init__(self, app, redis_pool=None, device_rpm: int = 10, org_rpm: int = 100):
        self.app = app
        self.redis_pool = redis_pool
        self.device_rpm = device_rpm
        self.org_rpm = org_rpm

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Skip paths that should not be rate limited
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            await self.app(scope, receive, send)
            return

        if any(s in path for s in _SKIP_CONTAINS):
            await self.app(scope, receive, send)
            return

        # Determine rate limit tier and identity
        tier, identity, limit = self._classify(scope, path)

        if tier and identity and self.redis_pool:
            blocked = await self._check_rate_limit(tier, identity, limit)
            if blocked:
                await self._send_429(send, blocked)
                return

        await self.app(scope, receive, send)

    def _classify(self, scope, path: str) -> tuple[Optional[str], Optional[str], int]:
        """Classify request into rate limit tier.

        Returns (tier, identity, limit) or (None, None, 0) to skip.
        """
        headers = dict(scope.get("headers", []))

        # Device routes: keyed by mTLS cert CN
        if path.startswith("/api/v1/devices/"):
            cn = headers.get(b"x-device-cert-cn", b"").decode("utf-8", errors="ignore")
            if cn:
                return "device", cn, self.device_rpm
            return None, None, 0

        # Org routes: keyed by org_id from URL path
        match = _ORG_ID_RE.search(path)
        if match:
            return "org", match.group(1), self.org_rpm

        return None, None, 0

    async def _check_rate_limit(self, tier: str, identity: str, limit: int) -> int:
        """Check rate limit. Returns seconds until window resets if blocked, else 0."""
        try:
            client = Redis(connection_pool=self.redis_pool)
            try:
                minute_bucket = int(time.time()) // 60
                key = f"rl:{tier}:{identity}:{minute_bucket}"

                count = await client.incr(key)
                if count == 1:
                    await client.expire(key, 60)

                if count > limit:
                    # Seconds until current window expires
                    ttl = await client.ttl(key)
                    return max(ttl, 1)
            finally:
                await client.aclose()
        except (RedisError, OSError, ConnectionError) as exc:
            # Graceful fallback: Redis failure = allow request
            logger.warning("Rate limiter Redis error (allowing request): %s", exc)

        return 0

    async def _send_429(self, send, retry_after: int):
        """Send 429 Too Many Requests response."""
        body = b'{"detail":"Rate limit exceeded"}'
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [
                [b"content-type", b"application/json"],
                [b"retry-after", str(retry_after).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
