"""Governed AI service — GDPR consent gate, redaction, blast-radius guard.

AI Layer Rules (CLAUDE.md):
- AI disabled by default. Explicit opt-in required per org.
- Before every Claude API call:
  1. Check ai_policy.external_ai_enabled
  2. Write audit_log entry with payload_hash (this write must succeed first)
  3. Only then make the API call
- Blast radius: nl_blast_radius_limit default 200 devices
- Model: claude-sonnet-4-20250514
"""

import copy
import hashlib
import json
import logging
import re
import uuid as _uuid
from typing import Optional

import anthropic
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.organizations import Organization
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services import audit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AI policy defaults
# ---------------------------------------------------------------------------

_DEFAULT_AI_POLICY = {
    "external_ai_enabled": False,
    "allowed_features": [],
    "redaction": {"hostnames": True, "ip_addresses": True},
    "nl_blast_radius_limit": 200,
    "nl_block_deploy_all": True,
}

# System prompt for fleet security assistant
_SYSTEM_PROMPT = (
    "You are a fleet security assistant for an organisation. "
    "Answer queries about vulnerability status, patch compliance, and deployment. "
    "Never suggest actions affecting more than 200 devices without explicit confirmation. "
    "All device identifiers in this context have been anonymised."
)

_COMPLIANCE_SYSTEM_PROMPT = (
    "You are a compliance report writer. Generate a concise 3-paragraph executive "
    "summary of the patch compliance data provided. Focus on: (1) overall posture, "
    "(2) key risks, (3) recommended actions. Use professional language suitable for "
    "executive and audit audiences. All device identifiers have been anonymised."
)

_DIAGNOSE_SYSTEM_PROMPT = (
    "You are a patch deployment diagnostic assistant. Analyse the failure data and "
    "return a JSON object with exactly these fields: "
    '{"likely_cause": "string", "confidence": float 0-1, '
    '"recommended_steps": ["step1", ...], "requires_human": bool}. '
    "All device identifiers have been anonymised."
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AIDisabledError(Exception):
    """AI features not enabled for this organisation."""

    pass


class AIFeatureDisabledError(Exception):
    """Specific AI feature not in allowed_features list."""

    pass


class BlastRadiusExceededError(Exception):
    """Query blast radius exceeds org limit for non-org_admin user."""

    def __init__(self, actual: int, limit: int):
        self.actual = actual
        self.limit = limit
        super().__init__(f"Blast radius {actual} exceeds limit {limit}")


class BlockedActionError(Exception):
    """Action blocked by org policy (e.g. 'all devices' pattern)."""

    pass


# ---------------------------------------------------------------------------
# Hostname / IP regex patterns
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BLAST_RADIUS_RE = re.compile(
    r"(?:affecting|deploy(?:ing)?\s+(?:to|across)?|patch(?:ing)?|"
    r"impact(?:ing)?|target(?:ing)?|updat(?:e|ing))\s+"
    r"(?:(?:all\s+)?(\d+)\s+(?:device|endpoint|machine|system|host)s?)",
    re.IGNORECASE,
)
_ALL_DEVICES_RE = re.compile(r"\ball\s+devices\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# AIRedactor
# ---------------------------------------------------------------------------


class AIRedactor:
    """Sanitise payloads before sending to external AI.

    Replaces hostnames with Device-{hash[:4]} and IPs with IP-{hash[:4]}.
    Builds a reverse redaction_map for de-redacting responses if needed.
    """

    def sanitize(
        self,
        payload: dict,
        policy: dict,
        hostnames: Optional[list[str]] = None,
    ) -> tuple[dict, dict]:
        """Return (sanitized_payload, redaction_map).

        redaction_map: {anonymised_name: original_name}
        """
        redaction_map: dict[str, str] = {}
        sanitized = copy.deepcopy(payload)

        redaction_cfg = policy.get("redaction", {"hostnames": True, "ip_addresses": True})

        # Collect hostnames to redact
        hostname_set: set[str] = set()
        if redaction_cfg.get("hostnames", True):
            if hostnames:
                hostname_set.update(hostnames)
            # Also extract hostnames from payload values
            self._collect_hostnames(payload, hostname_set)

        # Build hostname replacement map
        hostname_map: dict[str, str] = {}
        for hn in hostname_set:
            h = hashlib.sha256(hn.encode()).hexdigest()[:4]
            anon = f"Device-{h}"
            hostname_map[hn] = anon
            redaction_map[anon] = hn

        # Apply replacements
        if hostname_map:
            sanitized = self._replace_strings(sanitized, hostname_map)

        # IP redaction
        if redaction_cfg.get("ip_addresses", True):
            sanitized, ip_map = self._redact_ips(sanitized)
            redaction_map.update(ip_map)

        return sanitized, redaction_map

    def _collect_hostnames(self, obj, hostnames: set[str]) -> None:
        """Walk payload and collect values from known hostname keys."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("hostname", "hostnames", "device_name") and isinstance(v, str):
                    hostnames.add(v)
                elif k in ("hostnames",) and isinstance(v, list):
                    hostnames.update(v)
                else:
                    self._collect_hostnames(v, hostnames)
        elif isinstance(obj, list):
            for item in obj:
                self._collect_hostnames(item, hostnames)

    def _replace_strings(self, obj, replacements: dict[str, str]):
        """Recursively replace strings in dict/list structure."""
        if isinstance(obj, str):
            result = obj
            for original, replacement in replacements.items():
                result = result.replace(original, replacement)
            return result
        elif isinstance(obj, dict):
            return {k: self._replace_strings(v, replacements) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_strings(item, replacements) for item in obj]
        return obj

    def _redact_ips(self, obj) -> tuple:
        """Redact IPv4 addresses. Returns (redacted_obj, {anon: original})."""
        ip_map: dict[str, str] = {}

        def _redact_str(s: str) -> str:
            def _replace_ip(match: re.Match) -> str:
                ip = match.group(0)
                if ip not in ip_map.values():
                    h = hashlib.sha256(ip.encode()).hexdigest()[:4]
                    anon = f"IP-{h}"
                    # Check for collision
                    while anon in ip_map:
                        h = hashlib.sha256((ip + anon).encode()).hexdigest()[:4]
                        anon = f"IP-{h}"
                    ip_map[anon] = ip
                else:
                    # Find existing anon for this IP
                    anon = next(k for k, v in ip_map.items() if v == ip)
                return anon

            return _IP_RE.sub(_replace_ip, s)

        def _walk(o):
            if isinstance(o, str):
                return _redact_str(o)
            elif isinstance(o, dict):
                return {k: _walk(v) for k, v in o.items()}
            elif isinstance(o, list):
                return [_walk(item) for item in o]
            return o

        redacted = _walk(obj)
        return redacted, ip_map


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def estimate_blast_radius(ai_text: str) -> int:
    """Parse AI response for device count references.

    Returns the maximum device count found, or 0 if none.
    """
    counts = []
    for match in _BLAST_RADIUS_RE.finditer(ai_text):
        try:
            counts.append(int(match.group(1)))
        except (ValueError, TypeError, IndexError):
            pass

    # Also check for "all N devices/endpoints" pattern
    all_pattern = re.findall(
        r"all\s+(\d+)\s+(?:device|endpoint|machine|system|host)s?",
        ai_text,
        re.IGNORECASE,
    )
    for num_str in all_pattern:
        try:
            counts.append(int(num_str))
        except ValueError:
            pass

    return max(counts) if counts else 0


def render_template_report(report_data: dict) -> str:
    """Non-AI template fallback for compliance narration.

    Returns a structured summary when AI is disabled.
    """
    period = report_data.get("period_days", 30)
    total_exposed = report_data.get("total_exposed", 0)
    total_patched = report_data.get("total_patched", 0)
    patch_rate = report_data.get("patch_rate", 0)
    mttrem_p50 = report_data.get("mttrem_p50")
    top_unresolved = report_data.get("top_unresolved", [])

    pct = f"{patch_rate * 100:.1f}%" if patch_rate else "N/A"
    mttrem_str = f"{mttrem_p50:.1f} hours" if mttrem_p50 is not None else "N/A"

    unresolved_lines = ""
    for item in top_unresolved[:5]:
        cve = item.get("cve_id", "Unknown")
        count = item.get("device_count", 0)
        unresolved_lines += f"  - {cve}: {count} device(s) affected\n"

    return (
        f"Compliance Report — {period}-day period\n\n"
        f"In the past {period} days, {total_patched} of {total_exposed} "
        f"vulnerabilities were remediated ({pct} patch rate). "
        f"Median time-to-remediation (MTTRem p50) was {mttrem_str}.\n\n"
        f"Top unresolved exposures:\n{unresolved_lines}\n"
        f"This report was generated from system data without AI narration. "
        f"Enable AI features in organisation settings for enhanced analysis."
    )


# ---------------------------------------------------------------------------
# AIService
# ---------------------------------------------------------------------------


class AIService:
    """Governed AI service with GDPR consent gate, redaction, and blast-radius guard."""

    def __init__(self):
        self.redactor = AIRedactor()

    async def _get_org_ai_policy(self, db: AsyncSession, org_id: _uuid.UUID) -> dict:
        """Load org.settings.ai_policy with defaults."""
        org = await db.get(Organization, org_id)
        if not org:
            return dict(_DEFAULT_AI_POLICY)
        org_settings = org.settings or {}
        policy = dict(_DEFAULT_AI_POLICY)
        policy.update(org_settings.get("ai_policy", {}))
        return policy

    async def _build_fleet_context(self, db: AsyncSession, org_id: _uuid.UUID) -> dict:
        """Build org-scoped fleet context for AI queries. Invariant #16: org-scoped."""
        # Top 10 urgent device vulnerabilities
        top_vulns_stmt = (
            select(
                DeviceVulnerability.urgency_score,
                Vulnerability.cve_id,
                Vulnerability.cvss_base_score,
                Vulnerability.in_cisa_kev,
                Device.hostname,
            )
            .select_from(DeviceVulnerability.__table__)
            .join(Vulnerability.__table__, Vulnerability.id == DeviceVulnerability.vuln_id)
            .join(Device.__table__, Device.id == DeviceVulnerability.device_id)
            .where(
                DeviceVulnerability.org_id == org_id,
                DeviceVulnerability.status == "exposed",
            )
            .order_by(DeviceVulnerability.urgency_score.desc().nullslast())
            .limit(10)
        )
        result = await db.execute(top_vulns_stmt)
        top_vulns = [
            {
                "cve_id": r.cve_id,
                "cvss": float(r.cvss_base_score) if r.cvss_base_score else None,
                "in_kev": r.in_cisa_kev,
                "urgency_score": r.urgency_score,
                "hostname": r.hostname,
            }
            for r in result.all()
        ]

        # Recent 5 deployments
        deploys_stmt = (
            select(DeploymentJob.state, DeploymentJob.ring, DeploymentJob.failure_reason)
            .where(DeploymentJob.org_id == org_id)
            .order_by(DeploymentJob.created_at.desc())
            .limit(5)
        )
        deploy_result = await db.execute(deploys_stmt)
        recent_deploys = [
            {"state": r.state, "ring": r.ring, "failure_reason": r.failure_reason}
            for r in deploy_result.all()
        ]

        # Fleet health
        total_devices = (
            await db.execute(
                select(func.count()).select_from(Device).where(Device.org_id == org_id)
            )
        ).scalar() or 0

        exposed_count = (
            await db.execute(
                select(func.count())
                .select_from(DeviceVulnerability)
                .where(
                    DeviceVulnerability.org_id == org_id,
                    DeviceVulnerability.status == "exposed",
                )
            )
        ).scalar() or 0

        return {
            "top_vulnerabilities": top_vulns,
            "recent_deployments": recent_deploys,
            "fleet_health": {
                "total_devices": total_devices,
                "exposed_device_vulns": exposed_count,
            },
        }

    async def execute_nl_query(
        self,
        db: AsyncSession,
        org_id: _uuid.UUID,
        user_id: _uuid.UUID,
        query_text: str,
        user_role: str,
    ) -> dict:
        """Execute a natural language fleet query with full governance.

        Order (CLAUDE.md AI Layer Rules):
        1. Check consent → 2. Build context → 3. Sanitize →
        4. Audit BEFORE API call → 5. Call Claude → 6. Blast radius gate
        """
        # 1. Check consent
        policy = await self._get_org_ai_policy(db, org_id)
        if not policy.get("external_ai_enabled"):
            raise AIDisabledError("AI features not enabled for this organisation")
        if "nl_query" not in policy.get("allowed_features", []):
            raise AIFeatureDisabledError("nl_query not in allowed_features")

        # 2. Build context (org-scoped only — Invariant #16)
        context = await self._build_fleet_context(db, org_id)

        # 3. Sanitize
        sanitized_context, redaction_map = self.redactor.sanitize(context, policy)

        # 4. Write audit BEFORE API call — CRITICAL EVENT, must succeed
        payload_hash = hashlib.sha256(
            json.dumps(sanitized_context, sort_keys=True, default=str).encode()
        ).hexdigest()
        await audit.record(
            db,
            event_type="ai.external_call",
            org_id=org_id,
            user_id=user_id,
            ai_feature="nl_query",
            changes={
                "feature": "nl_query",
                "payload_hash": payload_hash,
                "redaction_fields": list(policy.get("redaction", {}).keys()),
            },
        )

        # 5. Call Claude API
        client = anthropic.AsyncAnthropic(api_key=settings.claude_api_key)
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"{query_text}\n\nContext: {json.dumps(sanitized_context, default=str)}",
                }
            ],
        )

        ai_text = response.content[0].text

        # 6. Estimate blast radius
        blast_radius = estimate_blast_radius(ai_text)

        # 7. Blast radius gate
        limit = policy.get("nl_blast_radius_limit", 200)
        if blast_radius > limit and user_role != "org_admin":
            # Audit the override attempt
            await audit.record(
                db,
                event_type="ai.blast_radius_override",
                org_id=org_id,
                user_id=user_id,
                ai_feature="nl_query",
                changes={"blast_radius": blast_radius, "limit": limit, "blocked": True},
            )
            raise BlastRadiusExceededError(blast_radius, limit)

        # 8. Block "all devices" pattern
        if policy.get("nl_block_deploy_all", True) and _ALL_DEVICES_RE.search(ai_text):
            raise BlockedActionError(
                "Queries affecting all devices require org_admin direct action"
            )

        return {
            "response": ai_text,
            "blast_radius": blast_radius,
            "requires_confirmation": blast_radius > 0,
            "redaction_active": bool(redaction_map),
        }

    async def narrate_compliance_report(
        self,
        db: AsyncSession,
        org_id: _uuid.UUID,
        user_id: _uuid.UUID,
        report_data: dict,
    ) -> dict:
        """Generate plain-language executive summary.

        Falls back to template if AI disabled — no API call made.
        """
        policy = await self._get_org_ai_policy(db, org_id)

        if not policy.get("external_ai_enabled"):
            return {
                "narrative": render_template_report(report_data),
                "ai_generated": False,
            }

        if "narrate_report" not in policy.get("allowed_features", []):
            return {
                "narrative": render_template_report(report_data),
                "ai_generated": False,
            }

        sanitized, _ = self.redactor.sanitize(report_data, policy)

        # Audit BEFORE API call — CRITICAL EVENT
        payload_hash = hashlib.sha256(
            json.dumps(sanitized, sort_keys=True, default=str).encode()
        ).hexdigest()
        await audit.record(
            db,
            event_type="ai.external_call",
            org_id=org_id,
            user_id=user_id,
            ai_feature="narrate_report",
            changes={
                "feature": "narrate_report",
                "payload_hash": payload_hash,
                "redaction_fields": list(policy.get("redaction", {}).keys()),
            },
        )

        client = anthropic.AsyncAnthropic(api_key=settings.claude_api_key)
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=_COMPLIANCE_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Generate an executive compliance summary:\n\n{json.dumps(sanitized, default=str)}",
                }
            ],
        )

        return {
            "narrative": response.content[0].text,
            "ai_generated": True,
        }

    async def diagnose_failure(
        self,
        db: AsyncSession,
        org_id: _uuid.UUID,
        user_id: _uuid.UUID,
        job_id: _uuid.UUID,
    ) -> dict:
        """Diagnose a deployment failure with AI.

        Returns structured: {likely_cause, confidence, recommended_steps, requires_human}.
        """
        policy = await self._get_org_ai_policy(db, org_id)
        if not policy.get("external_ai_enabled"):
            raise AIDisabledError("AI features not enabled for this organisation")
        if "diagnose_failure" not in policy.get("allowed_features", []):
            raise AIFeatureDisabledError("diagnose_failure not in allowed_features")

        # Load job context (org-scoped — Invariant #16)
        job = await db.get(DeploymentJob, job_id)
        if not job or job.org_id != org_id:
            raise ValueError(f"Job {job_id} not found in org {org_id}")

        job_context = {
            "state": job.state,
            "ring": job.ring,
            "failure_reason": job.failure_reason,
            "retry_count": job.retry_count,
            "telemetry_before": job.telemetry_before,
            "telemetry_after": job.telemetry_after,
        }

        sanitized, _ = self.redactor.sanitize(job_context, policy)

        # Audit BEFORE API call — CRITICAL EVENT
        payload_hash = hashlib.sha256(
            json.dumps(sanitized, sort_keys=True, default=str).encode()
        ).hexdigest()
        await audit.record(
            db,
            event_type="ai.external_call",
            org_id=org_id,
            user_id=user_id,
            ai_feature="diagnose_failure",
            changes={
                "feature": "diagnose_failure",
                "payload_hash": payload_hash,
                "job_id": str(job_id),
            },
        )

        client = anthropic.AsyncAnthropic(api_key=settings.claude_api_key)
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=_DIAGNOSE_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Diagnose this deployment failure:\n\n{json.dumps(sanitized, default=str)}",
                }
            ],
        )

        ai_text = response.content[0].text

        # Parse structured response
        try:
            parsed = json.loads(ai_text)
            return {
                "likely_cause": parsed.get("likely_cause", "Unknown"),
                "confidence": min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
                "recommended_steps": parsed.get("recommended_steps", []),
                "requires_human": parsed.get("requires_human", True),
            }
        except (json.JSONDecodeError, TypeError, ValueError):
            return {
                "likely_cause": ai_text[:500],
                "confidence": 0.3,
                "recommended_steps": ["Review AI response manually"],
                "requires_human": True,
            }
