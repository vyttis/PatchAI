"""AI router — governed AI endpoints with GDPR consent gate.

AI is disabled by default. External AI requires explicit org consent
(both a product choice and GDPR legal mechanism for EU→US data transfer).

All endpoints enforce tenant isolation via get_org_scope() (Invariant #16).
Audit log written BEFORE any external API call (Invariant #10).
"""

import logging
import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.models.organizations import Organization
from backend.app.schemas.ai import (
    AIPolicyResponse,
    AIPolicyUpdate,
    DiagnoseFailureRequest,
    DiagnoseFailureResponse,
    NarrateReportRequest,
    NarrateReportResponse,
    NLQueryRequest,
    NLQueryResponse,
)
from backend.app.schemas.auth import OrgScope
from backend.app.services import audit
from backend.app.services.ai import (
    AIDisabledError,
    AIFeatureDisabledError,
    AIService,
    BlastRadiusExceededError,
    BlockedActionError,
    _DEFAULT_AI_POLICY,
)
from backend.app.services.audit import AuditInsertError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["ai"])


# ---------------------------------------------------------------------------
# POST /ai/query — natural language fleet query
# ---------------------------------------------------------------------------


@router.post("/ai/query", response_model=NLQueryResponse)
async def nl_query(
    org_id: _uuid.UUID,
    body: NLQueryRequest,
    scope: OrgScope = Depends(get_org_scope),
    _auth: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Execute a natural language query about fleet security posture.

    Requires AI to be enabled for the org (GDPR consent gate).
    Audit log is written BEFORE the Claude API call (Invariant #10).
    """
    service = AIService()
    try:
        result = await service.execute_nl_query(
            db, scope.org_id, scope.user.id, body.query, scope.user.role
        )
        return NLQueryResponse(**result)
    except AIDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI features not enabled for this organisation",
        )
    except AIFeatureDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="nl_query feature not enabled in AI policy",
        )
    except BlastRadiusExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Blast radius ({exc.actual}) exceeds limit ({exc.limit})",
        )
    except BlockedActionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except AuditInsertError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit system unavailable — AI call cannot proceed",
        )


# ---------------------------------------------------------------------------
# POST /ai/narrate-report — compliance narrative
# ---------------------------------------------------------------------------


@router.post("/ai/narrate-report", response_model=NarrateReportResponse)
async def narrate_report(
    org_id: _uuid.UUID,
    body: NarrateReportRequest,
    scope: OrgScope = Depends(get_org_scope),
    _auth: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Generate a plain-language compliance narrative.

    Falls back to a structured template when AI is disabled — no error,
    just ai_generated=false in the response.
    """
    service = AIService()
    try:
        result = await service.narrate_compliance_report(
            db, scope.org_id, scope.user.id, body.report_data
        )
        return NarrateReportResponse(**result)
    except AuditInsertError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit system unavailable — AI call cannot proceed",
        )


# ---------------------------------------------------------------------------
# POST /ai/diagnose-failure — job failure diagnosis
# ---------------------------------------------------------------------------


@router.post("/ai/diagnose-failure", response_model=DiagnoseFailureResponse)
async def diagnose_failure(
    org_id: _uuid.UUID,
    body: DiagnoseFailureRequest,
    scope: OrgScope = Depends(get_org_scope),
    _auth: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Diagnose a deployment failure with AI assistance.

    Returns structured diagnosis: {likely_cause, confidence, steps, requires_human}.
    """
    service = AIService()
    try:
        result = await service.diagnose_failure(
            db, scope.org_id, scope.user.id, body.job_id
        )
        return DiagnoseFailureResponse(**result)
    except AIDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI features not enabled for this organisation",
        )
    except AIFeatureDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="diagnose_failure feature not enabled in AI policy",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except AuditInsertError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit system unavailable — AI call cannot proceed",
        )


# ---------------------------------------------------------------------------
# PUT /settings/ai-policy — update AI policy (org_admin only)
# ---------------------------------------------------------------------------


@router.put("/settings/ai-policy", response_model=AIPolicyResponse)
async def update_ai_policy(
    org_id: _uuid.UUID,
    body: AIPolicyUpdate,
    scope: OrgScope = Depends(get_org_scope),
    _auth: None = Depends(require_role("org_admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update org AI policy. Requires org_admin role.

    "org.settings_changed" is a CRITICAL event (Invariant #10):
    audit INSERT must succeed BEFORE settings change proceeds.
    """
    org = await db.get(Organization, scope.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    current_settings = dict(org.settings or {})
    current_ai = current_settings.get("ai_policy", dict(_DEFAULT_AI_POLICY))

    # Build changes dict (only fields that were provided)
    changes = {}
    if body.external_ai_enabled is not None:
        changes["external_ai_enabled"] = body.external_ai_enabled
    if body.allowed_features is not None:
        changes["allowed_features"] = body.allowed_features
    if body.redaction is not None:
        changes["redaction"] = body.redaction
    if body.nl_blast_radius_limit is not None:
        changes["nl_blast_radius_limit"] = body.nl_blast_radius_limit
    if body.nl_block_deploy_all is not None:
        changes["nl_block_deploy_all"] = body.nl_block_deploy_all

    if not changes:
        # No changes — return current policy
        policy = dict(_DEFAULT_AI_POLICY)
        policy.update(current_ai)
        return AIPolicyResponse(**policy)

    # CRITICAL: audit BEFORE writing settings (Invariant #10)
    try:
        await audit.record(
            db,
            event_type="org.settings_changed",
            org_id=scope.org_id,
            user_id=scope.user.id,
            resource="ai_policy",
            changes={"previous": current_ai, "updated_fields": changes},
        )
    except AuditInsertError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit system unavailable — settings change cannot proceed",
        )

    # Only after audit succeeds: merge changes
    new_ai = dict(_DEFAULT_AI_POLICY)
    new_ai.update(current_ai)
    new_ai.update(changes)

    current_settings["ai_policy"] = new_ai
    org.settings = current_settings
    await db.commit()

    return AIPolicyResponse(**new_ai)


# ---------------------------------------------------------------------------
# GET /settings/ai-policy — read AI policy
# ---------------------------------------------------------------------------


@router.get("/settings/ai-policy", response_model=AIPolicyResponse)
async def get_ai_policy(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Read current AI policy for the org."""
    org = await db.get(Organization, scope.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    current_settings = org.settings or {}
    policy = dict(_DEFAULT_AI_POLICY)
    policy.update(current_settings.get("ai_policy", {}))
    return AIPolicyResponse(**policy)
