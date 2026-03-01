"""Authentication dependencies — Supabase JWT validation.

Supabase Auth issues JWTs. FastAPI validates using SUPABASE_JWT_SECRET.
Custom claims in JWT: org_id (UUID as string), role (string).
These are added via a Supabase Auth hook (see supabase/hooks/custom_claims.sql).

Agents do NOT use JWT — they use mTLS only (Invariant #6).
"""

import uuid as _uuid
from functools import wraps
from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from backend.app.config import settings
from backend.app.schemas.auth import CurrentUser, OrgScope

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=True)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> CurrentUser:
    """Decode and validate Supabase JWT, returning the current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        user_id = payload.get("sub")
        org_id = payload.get("org_id")
        role = payload.get("role")
        if user_id is None or org_id is None or role is None:
            raise credentials_exception
        return CurrentUser(
            id=_uuid.UUID(user_id),
            org_id=_uuid.UUID(org_id),
            role=role,
        )
    except (JWTError, ValueError, KeyError):
        raise credentials_exception


async def get_org_scope(
    org_id: _uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
) -> OrgScope:
    """Validate that the current user belongs to the requested org.

    Security Invariant #16: tenant isolation — cross-org leak = existential incident.
    """
    if current_user.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: org_id mismatch",
        )
    return OrgScope(org_id=org_id, user=current_user)


def require_role(*roles: str) -> Callable:
    """Dependency factory that checks the current user has one of the given roles."""

    async def _check_role(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(roles)}",
            )
        return current_user

    return _check_role
