"""HardHeaderStrip ASGI middleware.

Security invariant #2: Strips X-Device-Cert-CN and X-Device-Cert-Fingerprint
from ALL incoming requests unconditionally at the ASGI layer, BEFORE
MTLSHeaderGuard runs. This prevents clients from spoofing mTLS identity headers.

NEVER remove this middleware.
"""

STRIPPED_HEADERS = {
    b"x-device-cert-cn",
    b"x-device-cert-fingerprint",
}


class HardHeaderStrip:
    """ASGI middleware that strips mTLS identity headers from all requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = scope.get("headers", [])
            scope["headers"] = [
                (name, value)
                for name, value in headers
                if name.lower() not in STRIPPED_HEADERS
            ]
        await self.app(scope, receive, send)
