"""Vulnerability matching — two strictly separate paths for OS and apps.

vuln_match_os:  Windows KB baseline + OS build → RemediationOsTarget
vuln_match_apps: Third-party software → CPE normalization → VulnerabilityProduct

These functions never share code. OS matching and app matching are independent.

Also: compute_urgency_score (formula from CLAUDE.md), ensure_unpatched_exposure,
and check_fleet_for_kev_exposure (replaces Phase 2B stub).
"""

import logging
import uuid as _uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Optional

from packaging.version import InvalidVersion, Version
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.remediations import (
    Remediation,
    RemediationOsTarget,
    RemediationVulnerability,
)
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.models.vulnerability_products import VulnerabilityProduct
from backend.app.services.normalization import (
    AppRecord,
    SoftwareNormalizerV2,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Urgency score formula (CLAUDE.md spec)
# ---------------------------------------------------------------------------

EXPOSURE_MULTIPLIERS: dict[str, float] = {
    "internet_facing": 1.5,
    "dmz": 1.3,
    "vpn_gateway": 1.2,
}


def compute_urgency_score(
    vuln: Vulnerability,
    device: Device,
    days_since_signal: int,
) -> int:
    """Compute urgency score per CLAUDE.md formula.

    base = (cvss / 10) * 40
    kev_mult = 2.0 if in_cisa_kev else 1.0
    epss_pts = epss_score * 20
    overdue_pts = min(15, days_overdue // 7 * 3)
    criticality_m = {critical: 1.5, high: 1.25, standard: 1.0, low: 0.75}
    exposure_m = max(EXPOSURE_MULTIPLIERS.get(t, 1.0) for t in device.tags) if device.tags else 1.0
    urgency = min(100, int((base * kev_mult + epss_pts + overdue_pts) * criticality_m * exposure_m))
    """
    base = (float(vuln.cvss_base_score or 0) / 10) * 40
    kev_mult = 2.0 if vuln.in_cisa_kev else 1.0
    epss_pts = float(vuln.epss_score or 0) * 20
    overdue_pts = min(15, (days_since_signal // 7) * 3)
    criticality_m = {"critical": 1.5, "high": 1.25, "standard": 1.0, "low": 0.75}.get(
        device.criticality, 1.0
    )
    exposure_m = 1.0
    if device.tags:
        tag_mults = [EXPOSURE_MULTIPLIERS.get(t, 1.0) for t in device.tags]
        if tag_mults:
            exposure_m = max(tag_mults)
    return min(100, int((base * kev_mult + epss_pts + overdue_pts) * criticality_m * exposure_m))


def _signal_ingested_at(vuln: Vulnerability) -> Optional[datetime]:
    """Determine when PatchPilot first knew about this CVE.

    Per CLAUDE.md: min(kev_added_date, published_at).
    """
    candidates: list[datetime] = []
    if vuln.kev_added_date:
        d = vuln.kev_added_date
        if isinstance(d, date) and not isinstance(d, datetime):
            d = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        candidates.append(d)
    if vuln.published_at:
        pub = vuln.published_at
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        candidates.append(pub)
    return min(candidates) if candidates else None


# ---------------------------------------------------------------------------
# OS path — KB baseline + OS build matching
# ---------------------------------------------------------------------------


async def vuln_match_os(db: AsyncSession, device_id: _uuid.UUID) -> int:
    """Match OS-level vulnerabilities for a device via KB baseline.

    Returns the number of new DeviceVulnerability rows created.
    """
    # Load device
    device = await db.get(Device, device_id)
    if device is None:
        logger.warning("vuln_match_os: device %s not found", device_id)
        return 0

    if not device.os_build:
        logger.debug("vuln_match_os: device %s has no os_build", device_id)
        return 0

    # Extract installed KBs from inventory data
    inv = device.inventory_section_hashes or {}
    installed_kbs: set[str] = set()
    kbs_data = inv.get("kbs_installed", [])
    if isinstance(kbs_data, list):
        installed_kbs = {str(kb) for kb in kbs_data}
    kbs_stale = inv.get("kbs_stale", False)

    # Query RemediationOsTargets matching this device's OS build
    stmt = (
        select(RemediationOsTarget)
        .where(RemediationOsTarget.os_build == device.os_build)
    )
    result = await db.execute(stmt)
    os_targets = result.scalars().all()

    created_count = 0
    for target in os_targets:
        # Check min_build_revision (UBR)
        if target.min_build_revision is not None:
            # Extract UBR from os_build if present (e.g., "19045.3803")
            parts = device.os_build.split(".")
            if len(parts) >= 2:
                try:
                    device_ubr = int(parts[-1])
                    if device_ubr >= target.min_build_revision:
                        continue  # Patched by build revision
                except ValueError:
                    pass  # Can't parse UBR, assume vulnerable

        # Load the remediation
        remediation = await db.get(Remediation, target.remediation_id)
        if remediation is None:
            continue

        # Check if KB is installed
        if remediation.external_id and remediation.external_id in installed_kbs:
            continue  # Already patched

        # Get linked vulnerabilities
        vuln_stmt = (
            select(Vulnerability)
            .join(
                RemediationVulnerability,
                RemediationVulnerability.vuln_id == Vulnerability.id,
            )
            .where(RemediationVulnerability.remediation_id == remediation.id)
        )
        vuln_result = await db.execute(vuln_stmt)
        vulns = vuln_result.scalars().all()

        for vuln in vulns:
            # Check if DeviceVulnerability already exists
            existing_stmt = select(DeviceVulnerability).where(
                DeviceVulnerability.device_id == device_id,
                DeviceVulnerability.vuln_id == vuln.id,
                DeviceVulnerability.org_id == device.org_id,
            )
            existing = await db.execute(existing_stmt)
            if existing.scalar_one_or_none():
                continue  # Already tracked

            signal_ts = _signal_ingested_at(vuln)
            days_since = 0
            if signal_ts:
                delta = datetime.now(timezone.utc) - signal_ts
                days_since = max(0, delta.days)

            dv = DeviceVulnerability(
                org_id=device.org_id,
                device_id=device_id,
                vuln_id=vuln.id,
                remediation_id=remediation.id,
                status="exposed",
                urgency_score=compute_urgency_score(vuln, device, days_since),
                signal_ingested_at=signal_ts,
                uncertain_baseline=kbs_stale,
            )
            db.add(dv)
            created_count += 1

    return created_count


# ---------------------------------------------------------------------------
# App path — CPE normalization + VulnerabilityProduct matching
# ---------------------------------------------------------------------------


def _compare_versions(app_version: str, vp: VulnerabilityProduct) -> bool:
    """Check if app_version falls within the vulnerable version range."""
    try:
        ver = Version(app_version)
    except InvalidVersion:
        return False  # Can't parse → skip (safe default)

    if vp.version_start_including:
        try:
            if ver < Version(vp.version_start_including):
                return False
        except InvalidVersion:
            pass

    if vp.version_end_excluding:
        try:
            if ver >= Version(vp.version_end_excluding):
                return False
        except InvalidVersion:
            pass

    if vp.version_end_including:
        try:
            if ver > Version(vp.version_end_including):
                return False
        except InvalidVersion:
            pass

    return True


async def vuln_match_apps(db: AsyncSession, device_id: _uuid.UUID) -> int:
    """Match third-party app vulnerabilities for a device via CPE normalization.

    Returns the number of new DeviceVulnerability rows + UnpatchedExposure rows created.
    """
    device = await db.get(Device, device_id)
    if device is None:
        logger.warning("vuln_match_apps: device %s not found", device_id)
        return 0

    inv = device.inventory_section_hashes or {}
    apps_data = inv.get("apps_inventory", [])
    if not isinstance(apps_data, list) or not apps_data:
        logger.debug("vuln_match_apps: device %s has no app inventory", device_id)
        return 0

    normalizer = SoftwareNormalizerV2(db, device.org_id)
    created_count = 0

    for app_dict in apps_data:
        raw = AppRecord.from_dict(app_dict)
        normalized = await normalizer.normalize(raw, device_id=device_id)

        # Skip low-confidence matches — no false positives
        if normalized.confidence < Decimal("0.60"):
            continue

        # Query VulnerabilityProduct for matching CPE vendor/product
        vp_stmt = select(VulnerabilityProduct).where(
            VulnerabilityProduct.cpe_vendor == normalized.vendor,
            VulnerabilityProduct.cpe_product == normalized.product,
        )
        vp_result = await db.execute(vp_stmt)
        vuln_products = vp_result.scalars().all()

        for vp in vuln_products:
            # Version range check
            if raw.version and not _compare_versions(raw.version, vp):
                continue

            # Load vulnerability
            vuln = await db.get(Vulnerability, vp.vuln_id)
            if vuln is None:
                continue

            # Check if already tracked
            existing_stmt = select(DeviceVulnerability).where(
                DeviceVulnerability.device_id == device_id,
                DeviceVulnerability.vuln_id == vuln.id,
                DeviceVulnerability.org_id == device.org_id,
            )
            existing = await db.execute(existing_stmt)
            if existing.scalar_one_or_none():
                continue

            # Get remediation (if any)
            rem_stmt = (
                select(Remediation)
                .join(
                    RemediationVulnerability,
                    RemediationVulnerability.remediation_id == Remediation.id,
                )
                .where(RemediationVulnerability.vuln_id == vuln.id)
                .limit(1)
            )
            rem_result = await db.execute(rem_stmt)
            remediation = rem_result.scalar_one_or_none()

            if remediation is None:
                # No remediation → create UnpatchedExposure (first-class entity!)
                # Language: "zero-day response" — NOT "zero-day detection" (Invariant #14)
                await ensure_unpatched_exposure(
                    db, vuln.id, device.org_id, affected_device_ids=[device_id],
                )
                created_count += 1
                continue

            signal_ts = _signal_ingested_at(vuln)
            days_since = 0
            if signal_ts:
                delta = datetime.now(timezone.utc) - signal_ts
                days_since = max(0, delta.days)

            dv = DeviceVulnerability(
                org_id=device.org_id,
                device_id=device_id,
                vuln_id=vuln.id,
                remediation_id=remediation.id,
                status="exposed",
                urgency_score=compute_urgency_score(vuln, device, days_since),
                signal_ingested_at=signal_ts,
                uncertain_baseline=False,
            )
            db.add(dv)
            created_count += 1

    return created_count


# ---------------------------------------------------------------------------
# Import bridge: ensure_unpatched_exposure canonical impl in zeroday_monitor
# ---------------------------------------------------------------------------

from backend.app.workers.zeroday_monitor import ensure_unpatched_exposure  # noqa: F401, E402


# ---------------------------------------------------------------------------
# Fleet check for KEV exposure (replaces Phase 2B stub)
# ---------------------------------------------------------------------------


async def check_fleet_for_kev_exposure(
    db: AsyncSession, cve_id: str,
) -> int:
    """Called by KEVFetcher when a new CVE is added to CISA KEV.

    Finds the Vulnerability, then triggers OS + app matching for all devices.
    Returns total new DeviceVulnerability/UnpatchedExposure rows created.
    """
    # Find the vulnerability by CVE ID
    vuln_stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
    vuln_result = await db.execute(vuln_stmt)
    vuln = vuln_result.scalar_one_or_none()
    if vuln is None:
        logger.warning("check_fleet_for_kev_exposure: CVE %s not found in DB", cve_id)
        return 0

    # Get all devices
    device_stmt = select(Device)
    device_result = await db.execute(device_stmt)
    devices = device_result.scalars().all()

    total_created = 0
    for device in devices:
        total_created += await vuln_match_os(db, device.id)
        total_created += await vuln_match_apps(db, device.id)

    logger.info(
        "check_fleet_for_kev_exposure(%s): %d new entries across %d devices",
        cve_id,
        total_created,
        len(devices),
    )
    return total_created
