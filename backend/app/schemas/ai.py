"""Pydantic schemas for the governed AI layer (Phase 4A).

AI is disabled by default. Every org must explicitly set
ai_policy.external_ai_enabled = true (GDPR consent gate).
"""

import uuid as _uuid
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# NL Query
# ---------------------------------------------------------------------------


class NLQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="Natural language fleet query")


class NLQueryResponse(BaseModel):
    response: str
    blast_radius: int
    requires_confirmation: bool
    redaction_active: bool


# ---------------------------------------------------------------------------
# Narrate Report
# ---------------------------------------------------------------------------


class NarrateReportRequest(BaseModel):
    report_data: dict = Field(..., description="Compliance report data to narrate")


class NarrateReportResponse(BaseModel):
    narrative: str
    ai_generated: bool  # False when template fallback used


# ---------------------------------------------------------------------------
# Diagnose Failure
# ---------------------------------------------------------------------------


class DiagnoseFailureRequest(BaseModel):
    job_id: _uuid.UUID


class DiagnoseFailureResponse(BaseModel):
    likely_cause: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    recommended_steps: list[str]
    requires_human: bool


# ---------------------------------------------------------------------------
# AI Policy
# ---------------------------------------------------------------------------


class AIPolicyUpdate(BaseModel):
    external_ai_enabled: Optional[bool] = None
    allowed_features: Optional[list[str]] = None
    redaction: Optional[dict] = None
    nl_blast_radius_limit: Optional[int] = Field(None, ge=1)
    nl_block_deploy_all: Optional[bool] = None


class AIPolicyResponse(BaseModel):
    external_ai_enabled: bool
    allowed_features: list[str]
    redaction: dict
    nl_blast_radius_limit: int
    nl_block_deploy_all: bool
