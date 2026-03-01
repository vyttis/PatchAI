"""Audit service — append-only audit log with blocking semantics for critical events.

Security Invariant #5:  audit_log INSERT-only at DB level.
Security Invariant #10: Critical events BLOCK if INSERT fails — raise AuditInsertError.
"""

import logging
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

CRITICAL_EVENTS = frozenset({
    "policy.evaluated",
    "deployment.dispatched",
    "cert.revoked",
    "cert.enrolled",
    "ai.external_call",
    "ai.blast_radius_override",
    "exposure.accepted_risk",
    "user.role_changed",
    "org.settings_changed",
})


class AuditInsertError(Exception):
    """Raised when a critical audit log INSERT fails.

    The caller's action MUST NOT proceed after this error.
    """

    pass


async def record(
    db: AsyncSession,
    *,
    event_type: str,
    org_id: _uuid.UUID,
    user_id: Optional[_uuid.UUID] = None,
    device_id: Optional[_uuid.UUID] = None,
    resource: Optional[str] = None,
    changes: Optional[dict] = None,
    ai_feature: Optional[str] = None,
    ip_address: Optional[str] = None,
    result: Optional[str] = None,
) -> None:
    """Record an audit log entry.

    For CRITICAL_EVENTS: INSERT must succeed or raise AuditInsertError.
    For other events: INSERT failure is logged as warning (best-effort).
    """
    is_critical = event_type in CRITICAL_EVENTS

    try:
        stmt = insert(AuditLog).values(
            id=_uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            org_id=org_id,
            user_id=user_id,
            device_id=device_id,
            event_type=event_type,
            resource=resource,
            changes=changes,
            ai_feature=ai_feature,
            ip_address=ip_address,
            result=result,
        )
        await db.execute(stmt)
        await db.flush()
    except Exception as exc:
        if is_critical:
            logger.critical(
                "CRITICAL audit INSERT failed for event=%s org=%s: %s",
                event_type,
                org_id,
                exc,
            )
            raise AuditInsertError(
                f"Critical audit log INSERT failed for {event_type}: {exc}"
            ) from exc
        else:
            logger.warning(
                "Non-critical audit INSERT failed for event=%s org=%s: %s",
                event_type,
                org_id,
                exc,
            )
