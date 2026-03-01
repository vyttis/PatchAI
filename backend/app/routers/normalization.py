"""Normalization admin endpoints — override and review unmatched software.

POST /api/v1/orgs/{org_id}/normalization-overrides — admin adds mapping
GET  /api/v1/orgs/{org_id}/normalization-review    — view unmatched entries
"""

import logging
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.models.software_normalization import (
    SoftwareNormalizationLog,
    TenantNormalizationOverride,
)
from backend.app.schemas.auth import OrgScope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["normalization"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class NormalizationOverrideRequest(BaseModel):
    display_name: str
    publisher: str
    vendor: str
    product: str
    action: str = "map"  # "map" or "ignore"


class NormalizationOverrideResponse(BaseModel):
    id: str
    match_key: str
    vendor: str
    product: str


class NormalizationReviewEntry(BaseModel):
    id: str
    device_id: str
    raw_display_name: Optional[str]
    raw_publisher: Optional[str]
    product_code: Optional[str]
    confidence: float
    match_method: Optional[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/normalization-overrides",
    response_model=NormalizationOverrideResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_normalization_override(
    body: NormalizationOverrideRequest,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create a tenant normalization override.

    Auth: JWT + org_admin/admin + org scope (Invariant #16).
    """
    match_key = f"{body.publisher}::{body.display_name}"

    # Check for existing override with same match_key
    existing_stmt = select(TenantNormalizationOverride).where(
        TenantNormalizationOverride.org_id == scope.org_id,
        TenantNormalizationOverride.match_key == match_key,
    )
    existing = await db.execute(existing_stmt)
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Override already exists for '{match_key}'",
        )

    override = TenantNormalizationOverride(
        org_id=scope.org_id,
        match_key=match_key,
        vendor=body.vendor,
        product=body.product,
        confirmed_by=scope.user.id,
        confirmed_at=datetime.now(timezone.utc),
    )
    db.add(override)
    await db.commit()
    await db.refresh(override)

    return NormalizationOverrideResponse(
        id=str(override.id),
        match_key=override.match_key,
        vendor=override.vendor,
        product=override.product,
    )


@router.get(
    "/normalization-review",
    response_model=list[NormalizationReviewEntry],
)
async def get_normalization_review(
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Return unmatched software entries (confidence = 0.0) for admin review.

    Auth: JWT + org scope (Invariant #16).
    """
    stmt = (
        select(SoftwareNormalizationLog)
        .where(
            SoftwareNormalizationLog.org_id == scope.org_id,
            SoftwareNormalizationLog.confidence == 0,
        )
        .order_by(SoftwareNormalizationLog.normalized_at.desc())
        .limit(100)
    )
    result = await db.execute(stmt)
    entries = result.scalars().all()

    return [
        NormalizationReviewEntry(
            id=str(e.id),
            device_id=str(e.device_id),
            raw_display_name=e.raw_display_name,
            raw_publisher=e.raw_publisher,
            product_code=e.product_code,
            confidence=float(e.confidence) if e.confidence is not None else 0.0,
            match_method=e.match_method,
        )
        for e in entries
    ]
