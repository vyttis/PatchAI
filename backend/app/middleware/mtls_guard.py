"""MTLSHeaderGuard middleware.

Runs AFTER HardHeaderStrip. At this point, X-Device-Cert-CN and
X-Device-Cert-Fingerprint can only come from the Fly.io proxy (mTLS
termination), never from the client.

This middleware validates that mTLS headers on requests from Fly.io internal
network (10.0.0.0/8) are passed through. Headers from external sources were
already stripped by HardHeaderStrip.

Actual device authentication is performed by the get_mtls_device() dependency.
"""

import ipaddress


# Fly.io internal network ranges
_FLY_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("fd00::/8"),
]


def _is_fly_internal(ip_str: str) -> bool:
    """Check if an IP address is in Fly.io's internal network range."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _FLY_INTERNAL_NETS)
    except (ValueError, AttributeError):
        return False


class MTLSHeaderGuard:
    """ASGI middleware that validates mTLS headers on agent routes.

    For requests from Fly.io internal network: mTLS headers are trusted
    (injected by Fly.io after mTLS termination).

    For external requests: HardHeaderStrip already removed the headers,
    so there's nothing additional to do here.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            # Only process agent routes that use mTLS
            if path.startswith("/api/v1/devices/") or path == "/api/v1/enrollment/enroll":
                headers = dict(scope.get("headers", []))
                xff = headers.get(b"x-forwarded-for", b"").decode()
                if xff:
                    # Use the first (leftmost) IP from X-Forwarded-For
                    client_ip = xff.split(",")[0].strip()
                    if not _is_fly_internal(client_ip):
                        # External request — HardHeaderStrip already removed
                        # mTLS headers. Nothing more to do.
                        pass

        await self.app(scope, receive, send)
