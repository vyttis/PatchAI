"""Deployment packs router — pack generation, token management, agent updates, internal releases.

Endpoints:
  POST /orgs/{org_id}/deployment-packs/generate — generate ZIP (JWT, org_admin)
  GET  /orgs/{org_id}/enrollment-tokens — list tokens (JWT, org_admin)
  DELETE /orgs/{org_id}/enrollment-tokens/{token_id} — revoke token (JWT, org_admin)
  GET  /agent/updates/check — agent version check (mTLS)
  POST /internal/releases — publish agent version (X-Internal-Key)
"""

import logging
import secrets as _secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from packaging.version import Version
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.dependencies.device_auth import get_mtls_device
from backend.app.models.agent_versions import AgentVersion
from backend.app.models.devices import Device
from backend.app.models.enrollment_tokens import EnrollmentToken
from backend.app.models.organizations import Organization
from backend.app.schemas.auth import CurrentUser, OrgScope
from backend.app.schemas.deployment_packs import (
    AgentUpdateCheckResponse,
    DeploymentPackRequest,
    EnrollmentTokenListItem,
    InternalReleaseRequest,
)
from backend.app.services.deployment_packs import generate_windows_pack

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["deployment-packs"])


# ---------------------------------------------------------------------------
# Internal key auth dependency
# ---------------------------------------------------------------------------


async def verify_internal_key(request: Request) -> None:
    """Verify X-Internal-Key header matches settings.internal_release_key."""
    key = request.headers.get("X-Internal-Key", "")
    if not settings.internal_release_key or not _secrets.compare_digest(
        key, settings.internal_release_key
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal key",
        )


# ---------------------------------------------------------------------------
# POST /orgs/{org_id}/deployment-packs/generate
# ---------------------------------------------------------------------------


@router.post("/orgs/{org_id}/deployment-packs/generate")
async def generate_deployment_pack(
    org_id: _uuid.UUID,
    body: DeploymentPackRequest,
    current_user: CurrentUser = Depends(require_role("org_admin")),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Generate a deployment pack ZIP for the specified platform."""
    if body.platform != "windows":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only 'windows' platform is supported",
        )

    # Fetch org name for Intune manifest
    org = await db.get(Organization, scope.org_id)
    org_name = org.name if org else "Organization"

    try:
        zip_bytes, token_id, token_secret = await generate_windows_pack(
            db=db,
            org_id=scope.org_id,
            dept_id=body.dept_id,
            label=body.label,
            max_uses=body.max_uses,
            expires_hours=body.expires_hours,
            org_name=org_name,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    await db.commit()

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"PatchPilot-Deploy-{body.label}-{date_str}.zip"

    return StreamingResponse(
        iter([zip_bytes]),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Enrollment-Token": f"{token_id}.{token_secret}",
        },
    )


# ---------------------------------------------------------------------------
# GET /orgs/{org_id}/enrollment-tokens
# ---------------------------------------------------------------------------


@router.get(
    "/orgs/{org_id}/enrollment-tokens",
    response_model=list[EnrollmentTokenListItem],
)
async def list_enrollment_tokens(
    org_id: _uuid.UUID,
    current_user: CurrentUser = Depends(require_role("org_admin")),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List active enrollment tokens. Token secrets are NEVER returned."""
    result = await db.execute(
        select(EnrollmentToken)
        .where(EnrollmentToken.org_id == scope.org_id)
        .order_by(EnrollmentToken.created_at.desc())
    )
    tokens = result.scalars().all()
    return [
        EnrollmentTokenListItem(
            token_id=t.token_id,
            org_id=t.org_id,
            dept_id=t.dept_id,
            label=t.label,
            expires_at=t.expires_at,
            max_uses=t.max_uses,
            used_count=t.used_count,
            created_at=t.created_at,
        )
        for t in tokens
    ]


# ---------------------------------------------------------------------------
# DELETE /orgs/{org_id}/enrollment-tokens/{token_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/orgs/{org_id}/enrollment-tokens/{token_id}",
    status_code=204,
)
async def revoke_enrollment_token(
    org_id: _uuid.UUID,
    token_id: str,
    current_user: CurrentUser = Depends(require_role("org_admin")),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an enrollment token by deleting it. Invariant #16: tenant isolation."""
    result = await db.execute(
        select(EnrollmentToken).where(
            EnrollmentToken.token_id == token_id,
            EnrollmentToken.org_id == scope.org_id,
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )
    await db.delete(token)
    await db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# GET /agent/updates/check
# ---------------------------------------------------------------------------


@router.get("/agent/updates/check", response_model=AgentUpdateCheckResponse)
async def check_agent_update(
    platform: str = Query(default="windows"),
    current_version: str = Query(...),
    device: Device = Depends(get_mtls_device),
    db: AsyncSession = Depends(get_db),
):
    """Check if an agent update is available. Auth: mTLS (Invariant #6)."""
    result = await db.execute(
        select(AgentVersion).where(AgentVersion.is_latest == True).limit(1)  # noqa: E712
    )
    latest = result.scalar_one_or_none()

    if not latest:
        return AgentUpdateCheckResponse(update_available=False)

    try:
        current = Version(current_version)
        latest_ver = Version(latest.version)
    except Exception:
        return AgentUpdateCheckResponse(update_available=False)

    update_available = latest_ver > current

    force_update = False
    if latest.minimum_supported_version:
        try:
            min_ver = Version(latest.minimum_supported_version)
            force_update = current < min_ver
        except Exception:
            pass

    return AgentUpdateCheckResponse(
        update_available=update_available or force_update,
        version=latest.version if (update_available or force_update) else None,
        download_url=latest.windows_msi_url if (update_available or force_update) else None,
        sha256=latest.windows_sha256 if (update_available or force_update) else None,
        release_notes=latest.release_notes if (update_available or force_update) else None,
        force_update=force_update,
    )


# ---------------------------------------------------------------------------
# POST /internal/releases
# ---------------------------------------------------------------------------


@router.post("/internal/releases", status_code=201, dependencies=[Depends(verify_internal_key)])
async def create_internal_release(
    body: InternalReleaseRequest,
    db: AsyncSession = Depends(get_db),
):
    """Publish a new agent version. Auth: X-Internal-Key header (CI/CD pipeline)."""
    # Unset previous is_latest
    await db.execute(
        update(AgentVersion).where(AgentVersion.is_latest == True).values(is_latest=False)  # noqa: E712
    )

    agent_version = AgentVersion(
        version=body.version,
        windows_msi_url=body.msi_url,
        windows_sha256=body.sha256,
        windows_sig_url=body.sig_url,
        release_notes=body.release_notes,
        is_latest=True,
        released_at=datetime.now(timezone.utc),
    )
    db.add(agent_version)
    await db.commit()

    return {"version": body.version, "is_latest": True}
