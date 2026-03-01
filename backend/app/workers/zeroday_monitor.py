"""Zero-day response monitor — UnpatchedExposure lifecycle management.

Language: "zero-day RESPONSE" everywhere. Never "zero-day detection" (Invariant #14).

This module owns:
  - ensure_unpatched_exposure(): create/update when vuln_match_apps finds no remediation
  - recheck_unpatched_exposures(): Celery Beat hourly — auto-transition when patch appears
  - format_exposure_notification(): notification template for zero-day response alerts
"""

import logging
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.advisories import Advisory, AdvisoryVulnerability
from backend.app.models.remediations import Remediation, RemediationVulnerability
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services import audit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Interval parsing helper
# ---------------------------------------------------------------------------


def _parse_interval(text: Optional[str]) -> timedelta:
    """Parse simple interval strings like '1 hour', '30 minutes', '2 hours'."""
    if not text:
        return timedelta(hours=1)
    text = text.strip().lower()
    parts = text.split()
    if len(parts) == 2:
        try:
            value = int(parts[0])
        except ValueError:
            return timedelta(hours=1)
        unit = parts[1].rstrip("s")  # normalize "hours" -> "hour"
        if unit == "hour":
            return timedelta(hours=value)
        if unit == "minute":
            return timedelta(minutes=value)
        if unit == "day":
            return timedelta(days=value)
    return timedelta(hours=1)


# ---------------------------------------------------------------------------
# Mitigation extraction
# ---------------------------------------------------------------------------


async def _extract_mitigations(
    db: AsyncSession, vuln_id: _uuid.UUID,
) -> Optional[dict]:
    """Look up Advisory for this vuln via AdvisoryVulnerability join.

    Since the Advisory model has no dedicated mitigations field, we extract
    advisory_url and title as the best available mitigation reference.
    """
    stmt = (
        select(Advisory)
        .join(
            AdvisoryVulnerability,
            AdvisoryVulnerability.advisory_id == Advisory.id,
        )
        .where(AdvisoryVulnerability.vuln_id == vuln_id)
        .limit(1)
    )
    result = await db.execute(stmt)
    advisory = result.scalar_one_or_none()
    if advisory:
        return {
            "source": advisory.source,
            "advisory_url": advisory.advisory_url,
            "title": advisory.title,
            "severity": advisory.severity,
        }
    return None


# ---------------------------------------------------------------------------
# Notification template
# ---------------------------------------------------------------------------


def format_exposure_notification(
    vuln: Vulnerability,
    exposure: UnpatchedExposure,
    dept_breakdown: Optional[dict] = None,
) -> dict:
    """Format a zero-day RESPONSE notification.

    Language: "ZERO-DAY RESPONSE" in subject. Never "detection" (Invariant #14).

    Returns dict with 'subject' and 'body' keys.
    """
    title = vuln.description or "N/A"
    if len(title) > 80:
        title = title[:77] + "..."

    subject = f"[ZERO-DAY RESPONSE \u2014 NO PATCH] {vuln.cve_id}: {title}"

    kev_date_str = str(vuln.kev_added_date) if vuln.kev_added_date else "N/A"
    next_recheck = None
    if exposure.last_checked_at:
        interval = _parse_interval(exposure.recheck_interval)
        next_recheck = exposure.last_checked_at + interval

    mitigations_text = "No official mitigations published."
    if exposure.mitigations:
        parts = []
        if exposure.mitigations.get("advisory_url"):
            parts.append(f"Advisory: {exposure.mitigations['advisory_url']}")
        if exposure.mitigations.get("title"):
            parts.append(f"Title: {exposure.mitigations['title']}")
        if parts:
            mitigations_text = "\n".join(parts)

    dept_text = "N/A"
    if dept_breakdown:
        dept_text = ", ".join(
            f"{name}: {count}" for name, count in dept_breakdown.items()
        )

    body = (
        f"CVE: {vuln.cve_id} | CVSS: {float(vuln.cvss_base_score or 0):.1f} "
        f"| EPSS: {float(vuln.epss_score or 0):.4f} "
        f"| KEV Date: {kev_date_str}\n"
        f"\n"
        f"{exposure.affected_count} endpoints in your fleet are exposed.\n"
        f"Department breakdown: {dept_text}\n"
        f"\n"
        f"No patch exists yet. Vendor-provided mitigations:\n"
        f"{mitigations_text}\n"
        f"\n"
        f"PatchPilot will notify you immediately when a patch becomes available.\n"
        f"Next recheck: {next_recheck or 'scheduled'}"
    )

    return {"subject": subject, "body": body}


# ---------------------------------------------------------------------------
# ensure_unpatched_exposure — canonical implementation
# ---------------------------------------------------------------------------


async def ensure_unpatched_exposure(
    db: AsyncSession,
    vuln_id: _uuid.UUID,
    org_id: _uuid.UUID,
    affected_device_ids: Optional[list[_uuid.UUID]] = None,
) -> UnpatchedExposure:
    """Create or update an UnpatchedExposure for (org_id, vuln_id).

    Called when vuln_match_apps finds a match with no remediation.
    Creates or updates UnpatchedExposure. Never creates device_vulnerability
    with NULL remediation — the UnpatchedExposure IS the first-class entity.

    UNIQUE constraint on (org_id, vuln_id) ensures no duplicates.
    """
    # Check existing
    stmt = select(UnpatchedExposure).where(
        UnpatchedExposure.org_id == org_id,
        UnpatchedExposure.vuln_id == vuln_id,
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    count = len(affected_device_ids) if affected_device_ids else 1

    if existing:
        existing.affected_count = max(existing.affected_count or 0, count)
        return existing

    # New exposure — extract mitigations from advisory
    mitigations = await _extract_mitigations(db, vuln_id)

    exposure = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln_id,
        affected_count=count,
        mitigations=mitigations,
        status="open",
        last_checked_at=datetime.now(timezone.utc),
    )
    db.add(exposure)
    await db.flush()

    # Audit — non-critical (best-effort)
    vuln = await db.get(Vulnerability, vuln_id)
    cve_id = vuln.cve_id if vuln else str(vuln_id)
    try:
        await audit.record(
            db,
            event_type="exposure.created",
            org_id=org_id,
            resource=f"exposure:{exposure.id}",
            changes={
                "cve_id": cve_id,
                "affected_count": count,
                "status": "open",
            },
        )
    except Exception:
        logger.warning("Failed to write audit for new exposure %s", cve_id)

    return exposure


# ---------------------------------------------------------------------------
# Recheck loop — Celery Beat every 1h
# ---------------------------------------------------------------------------


async def recheck_unpatched_exposures(db: AsyncSession) -> dict:
    """For each open UnpatchedExposure: has a patch appeared?

    If a Remediation now exists for the vuln → auto-transition to "patched".
    Otherwise update last_checked_at.

    Returns summary dict with counts.
    """
    stmt = select(UnpatchedExposure).where(
        UnpatchedExposure.status.in_(["open", "mitigated"]),
    )
    result = await db.execute(stmt)
    open_exposures = result.scalars().all()

    patched = 0
    rechecked = 0
    now = datetime.now(timezone.utc)

    for exposure in open_exposures:
        # Has a remediation appeared for this vuln?
        rem_stmt = (
            select(Remediation)
            .join(
                RemediationVulnerability,
                RemediationVulnerability.remediation_id == Remediation.id,
            )
            .where(RemediationVulnerability.vuln_id == exposure.vuln_id)
            .limit(1)
        )
        rem_result = await db.execute(rem_stmt)
        new_remediation = rem_result.scalar_one_or_none()

        if new_remediation:
            # Patch available — transition exposure
            exposure.status = "patched"
            exposure.patched_at = now
            # Store deployment recommendation
            existing_mitigations = exposure.mitigations or {}
            existing_mitigations["deployment_recommendation"] = {
                "remediation_id": str(new_remediation.id),
                "title": new_remediation.title,
                "recommended_at": now.isoformat(),
            }
            exposure.mitigations = existing_mitigations

            try:
                await audit.record(
                    db,
                    event_type="exposure.remediation_found",
                    org_id=exposure.org_id,
                    resource=f"exposure:{exposure.id}",
                    changes={
                        "remediation_id": str(new_remediation.id),
                        "remediation_title": new_remediation.title,
                        "previous_status": "open",
                        "new_status": "patched",
                    },
                )
            except Exception:
                logger.warning(
                    "Failed to write audit for patched exposure %s", exposure.id,
                )
            patched += 1
        else:
            # Still no patch — update last_checked_at
            exposure.last_checked_at = now
            try:
                await audit.record(
                    db,
                    event_type="exposure.rechecked",
                    org_id=exposure.org_id,
                    resource=f"exposure:{exposure.id}",
                    changes={"result": "still_open", "checked_at": now.isoformat()},
                )
            except Exception:
                logger.warning(
                    "Failed to write audit for rechecked exposure %s", exposure.id,
                )
            rechecked += 1

    logger.info(
        "recheck_unpatched_exposures: %d patched, %d rechecked, %d total",
        patched,
        rechecked,
        len(open_exposures),
    )
    return {"patched": patched, "rechecked": rechecked, "total": len(open_exposures)}
