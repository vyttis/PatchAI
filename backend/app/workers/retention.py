"""GDPR data retention cleanup — daily 04:00 UTC Celery Beat task.

Cleans up:
1. Non-critical audit_log entries older than org's data_retention.audit_days (default 365)
2. Processed intel_feed_blobs older than data_retention.blob_days (default 90)

Invariant #5:  audit_log is INSERT-only at DB level for patchpilot_app role.
               In production, this task requires a dedicated patchpilot_retention role
               with scoped DELETE on audit_log (excluding CRITICAL_EVENTS).
               Logic is correct and tested with SQLite.

Invariant #8:  Never delete parse_error blobs — provenance must be preserved.
Invariant #10: Never delete CRITICAL_EVENTS audit entries.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.audit_log import AuditLog
from backend.app.models.intel_feeds import IntelFeedBlob
from backend.app.models.organizations import Organization
from backend.app.services.audit import CRITICAL_EVENTS

logger = logging.getLogger(__name__)

_DEFAULT_AUDIT_DAYS = 365
_DEFAULT_BLOB_DAYS = 90


async def gdpr_retention_cleanup(db: AsyncSession) -> dict:
    """Run GDPR data retention cleanup across all organisations.

    Returns {"audit_deleted": int, "blobs_deleted": int}.
    """
    now = datetime.now(timezone.utc)
    total_audit_deleted = 0
    total_blobs_deleted = 0

    # Process per-org audit retention
    orgs_result = await db.execute(select(Organization))
    orgs = orgs_result.scalars().all()

    for org in orgs:
        retention = (org.settings or {}).get("data_retention", {})
        audit_days = retention.get("audit_days", _DEFAULT_AUDIT_DAYS)
        audit_cutoff = now - timedelta(days=audit_days)

        # Delete non-critical audit entries older than audit_days
        audit_stmt = (
            delete(AuditLog)
            .where(
                AuditLog.org_id == org.id,
                AuditLog.timestamp < audit_cutoff,
                AuditLog.event_type.notin_(CRITICAL_EVENTS),
            )
        )
        result = await db.execute(audit_stmt)
        deleted = result.rowcount
        if deleted:
            logger.info(
                "Retention: deleted %d non-critical audit entries for org=%s (cutoff=%s)",
                deleted,
                org.id,
                audit_cutoff.isoformat(),
            )
        total_audit_deleted += deleted

    # Process intel feed blob retention (global, not per-org)
    # Use the minimum blob_days across all orgs, or default
    blob_days = _DEFAULT_BLOB_DAYS
    for org in orgs:
        retention = (org.settings or {}).get("data_retention", {})
        org_blob_days = retention.get("blob_days", _DEFAULT_BLOB_DAYS)
        blob_days = min(blob_days, org_blob_days)

    blob_cutoff = now - timedelta(days=blob_days)
    blob_stmt = (
        delete(IntelFeedBlob)
        .where(
            IntelFeedBlob.status == "processed",
            IntelFeedBlob.fetched_at < blob_cutoff,
        )
    )
    blob_result = await db.execute(blob_stmt)
    total_blobs_deleted = blob_result.rowcount
    if total_blobs_deleted:
        logger.info(
            "Retention: deleted %d processed intel blobs (cutoff=%s)",
            total_blobs_deleted,
            blob_cutoff.isoformat(),
        )

    logger.info(
        "GDPR retention cleanup complete: audit=%d, blobs=%d",
        total_audit_deleted,
        total_blobs_deleted,
    )
    return {"audit_deleted": total_audit_deleted, "blobs_deleted": total_blobs_deleted}
