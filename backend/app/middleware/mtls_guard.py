"""MTLSHeaderGuard middleware.

Runs AFTER HardHeaderStrip. At this point, X-Device-Cert-CN and
X-Device-Cert-Fingerprint can only come from the Fly.io proxy (mTLS
termination), never from the client.

This middleware validates that agent-only routes have the required
mTLS headers present. Implementation details will be filled in Phase 1B.
"""


class MTLSHeaderGuard:
    """ASGI middleware that validates mTLS headers on agent routes."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Phase 1B: validate mTLS headers for /api/v1/agent/* routes
        await self.app(scope, receive, send)
