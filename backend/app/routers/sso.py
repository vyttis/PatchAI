"""SSO stub endpoints — placeholders for SAML and OIDC integration.

Returns 501 Not Implemented for both SAML ACS and OIDC callback.
These are callback URLs that identity providers would POST to.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["auth"])


@router.post("/api/v1/auth/saml/acs")
async def saml_acs():
    """SAML Assertion Consumer Service — not yet implemented."""
    return JSONResponse(
        status_code=501,
        content={"detail": "SAML SSO is not yet implemented. Contact support for SSO timeline."},
    )


@router.post("/api/v1/auth/oidc/callback")
async def oidc_callback():
    """OIDC callback endpoint — not yet implemented."""
    return JSONResponse(
        status_code=501,
        content={"detail": "OIDC SSO is not yet implemented. Contact support for SSO timeline."},
    )
