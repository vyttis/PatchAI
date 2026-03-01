"""PatchPilot ORM models — all customer-data models inherit TenantMixin."""

from backend.app.models.advisories import Advisory, AdvisoryVulnerability
from backend.app.models.agent_versions import AgentVersion
from backend.app.models.audit_log import AuditLog
from backend.app.models.base import TenantMixin, TimestampMixin
from backend.app.models.deletion_requests import DeletionRequest
from backend.app.models.departments import Department
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.enrollment_tokens import EnrollmentToken
from backend.app.models.intel_feeds import IntelFeedBlob, IntelFeedHealth, IntelLastGood
from backend.app.models.nis2_incidents import NIS2Incident
from backend.app.models.org_cas import OrgCA
from backend.app.models.organizations import Organization
from backend.app.models.remediations import (
    Remediation,
    RemediationOsTarget,
    RemediationVulnerability,
)
from backend.app.models.software_normalization import (
    SoftwareNormalizationLog,
    TenantNormalizationOverride,
)
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.users import User
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.models.vulnerability_products import VulnerabilityProduct

__all__ = [
    "Advisory",
    "AdvisoryVulnerability",
    "AgentVersion",
    "AuditLog",
    "DeletionRequest",
    "Department",
    "DeploymentJob",
    "DeviceVulnerability",
    "Device",
    "EnrollmentToken",
    "IntelFeedBlob",
    "IntelFeedHealth",
    "IntelLastGood",
    "NIS2Incident",
    "OrgCA",
    "Organization",
    "Remediation",
    "RemediationOsTarget",
    "RemediationVulnerability",
    "SoftwareNormalizationLog",
    "TenantNormalizationOverride",
    "TenantMixin",
    "TimestampMixin",
    "UnpatchedExposure",
    "User",
    "Vulnerability",
    "VulnerabilityProduct",
]
