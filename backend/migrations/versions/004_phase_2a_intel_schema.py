"""Phase 2A: Intel pipeline schema — vulnerabilities, advisories, remediations,
device_vulnerabilities (with mttrem_hours generated column), unpatched_exposures,
intel feed tables, deployment_jobs, software normalization, and mttrem_by_ring view.

Revision ID: 004_phase_2a
Revises: 003_phase_1d
Create Date: 2026-03-01
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "004_phase_2a"
down_revision: Union[str, None] = "003_phase_1d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -----------------------------------------------------------------------
    # vulnerabilities
    # -----------------------------------------------------------------------
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("cve_id", sa.Text(), unique=True, nullable=False),
        sa.Column("cvss_base_score", sa.Numeric(3, 1)),
        sa.Column("cvss_vector", sa.Text()),
        sa.Column("epss_score", sa.Numeric(5, 4)),
        sa.Column("epss_percentile", sa.Numeric(5, 4)),
        sa.Column("in_cisa_kev", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("kev_added_date", sa.Date()),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("last_modified_at", sa.DateTime(timezone=True)),
        sa.Column("description", sa.Text()),
        sa.Column("references", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # vulnerability_products
    # -----------------------------------------------------------------------
    op.create_table(
        "vulnerability_products",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("cpe_vendor", sa.Text()),
        sa.Column("cpe_product", sa.Text()),
        sa.Column("version_start_including", sa.Text()),
        sa.Column("version_end_excluding", sa.Text()),
        sa.Column("version_end_including", sa.Text()),
    )

    # -----------------------------------------------------------------------
    # advisories
    # -----------------------------------------------------------------------
    op.create_table(
        "advisories",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source", sa.Text(), nullable=False, comment="msrc | vendor"),
        sa.Column("external_id", sa.Text(), unique=True, nullable=False),
        sa.Column("title", sa.Text()),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("severity", sa.Text()),
        sa.Column("advisory_url", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # advisory_vulnerabilities (join table)
    # -----------------------------------------------------------------------
    op.create_table(
        "advisory_vulnerabilities",
        sa.Column(
            "advisory_id",
            sa.Uuid(),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # -----------------------------------------------------------------------
    # remediations
    # -----------------------------------------------------------------------
    op.create_table(
        "remediations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source", sa.Text()),
        sa.Column("external_id", sa.Text()),
        sa.Column("title", sa.Text()),
        sa.Column("playbook", sa.JSON(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # remediation_vulnerabilities (join table)
    # -----------------------------------------------------------------------
    op.create_table(
        "remediation_vulnerabilities",
        sa.Column(
            "remediation_id",
            sa.Uuid(),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # -----------------------------------------------------------------------
    # remediation_os_targets
    # -----------------------------------------------------------------------
    op.create_table(
        "remediation_os_targets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "remediation_id",
            sa.Uuid(),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("os_build", sa.Text(), nullable=False),
        sa.Column("min_build_revision", sa.Integer()),
    )

    # -----------------------------------------------------------------------
    # device_vulnerabilities (tenant-scoped, mttrem_hours generated column)
    # -----------------------------------------------------------------------
    op.create_table(
        "device_vulnerabilities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "device_id",
            sa.Uuid(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "remediation_id",
            sa.Uuid(),
            sa.ForeignKey("remediations.id", ondelete="SET NULL"),
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default="exposed"),
        sa.Column("urgency_score", sa.Integer()),
        sa.Column("signal_ingested_at", sa.DateTime(timezone=True)),
        sa.Column("patched_at", sa.DateTime(timezone=True)),
        sa.Column("uncertain_baseline", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "mttrem_hours",
            sa.Numeric(),
            sa.Computed("EXTRACT(EPOCH FROM (patched_at - signal_ingested_at)) / 3600"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # unpatched_exposures (tenant-scoped, unique per org+vuln)
    # -----------------------------------------------------------------------
    op.create_table(
        "unpatched_exposures",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "vuln_id",
            sa.Uuid(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("affected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mitigations", sa.JSON()),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("patched_at", sa.DateTime(timezone=True)),
        sa.Column("recheck_interval", sa.Text(), server_default="1 hour"),
        sa.UniqueConstraint("org_id", "vuln_id", name="uq_unpatched_exposure_org_vuln"),
    )

    # -----------------------------------------------------------------------
    # intel_feed_blobs
    # -----------------------------------------------------------------------
    op.create_table(
        "intel_feed_blobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("feed_source", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("blob_hash", sa.Text(), nullable=False),
        sa.Column("byte_size", sa.Integer()),
        sa.Column("entity_count", sa.Integer()),
        sa.Column("storage_path", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text()),
    )

    # -----------------------------------------------------------------------
    # intel_feed_health
    # -----------------------------------------------------------------------
    op.create_table(
        "intel_feed_health",
        sa.Column("feed_source", sa.Text(), primary_key=True),
        sa.Column("last_fetched_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parse_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_parse_error", sa.Text()),
        sa.Column("last_parse_error_at", sa.DateTime(timezone=True)),
        sa.Column("is_stale", sa.Boolean(), nullable=False, server_default="false"),
    )

    # -----------------------------------------------------------------------
    # intel_last_good
    # -----------------------------------------------------------------------
    op.create_table(
        "intel_last_good",
        sa.Column("feed_source", sa.Text(), primary_key=True),
        sa.Column("data", sa.LargeBinary()),
        sa.Column("stored_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # deployment_jobs (tenant-scoped — schema needed for mttrem_by_ring view)
    # -----------------------------------------------------------------------
    op.create_table(
        "deployment_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "device_id",
            sa.Uuid(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "remediation_id",
            sa.Uuid(),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("ring", sa.Text()),
        sa.Column("state", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("state_updated_at", sa.DateTime(timezone=True)),
        sa.Column("playbook_snapshot", sa.JSON()),
        sa.Column("telemetry_before", sa.JSON()),
        sa.Column("telemetry_after", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # software_normalization_log (tenant-scoped)
    # -----------------------------------------------------------------------
    op.create_table(
        "software_normalization_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "device_id",
            sa.Uuid(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("raw_display_name", sa.Text()),
        sa.Column("raw_publisher", sa.Text()),
        sa.Column("product_code", sa.Text()),
        sa.Column("normalized_vendor", sa.Text()),
        sa.Column("normalized_product", sa.Text()),
        sa.Column("confidence", sa.Numeric(3, 2)),
        sa.Column("match_method", sa.Text()),
        sa.Column("normalized_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # tenant_normalization_overrides (tenant-scoped)
    # -----------------------------------------------------------------------
    op.create_table(
        "tenant_normalization_overrides",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("match_key", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column(
            "confirmed_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("confirmed_at", sa.DateTime(timezone=True)),
    )

    # -----------------------------------------------------------------------
    # DB VIEW: mttrem_by_ring (PostgreSQL only — uses percentile_cont)
    # This view is created via raw SQL because Alembic has no create_view op.
    # On SQLite (tests), this view won't exist — tests query the table directly.
    # -----------------------------------------------------------------------
    op.execute("""
        CREATE OR REPLACE VIEW mttrem_by_ring AS
        SELECT
            dv.org_id,
            dj.ring,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY dv.mttrem_hours) AS p50,
            percentile_cont(0.9) WITHIN GROUP (ORDER BY dv.mttrem_hours) AS p90,
            avg(dv.mttrem_hours) AS avg_hours,
            count(*) AS sample_count
        FROM device_vulnerabilities dv
        JOIN deployment_jobs dj
            ON dj.device_id = dv.device_id
            AND dj.remediation_id = dv.remediation_id
        WHERE dv.patched_at IS NOT NULL
            AND dv.mttrem_hours IS NOT NULL
        GROUP BY dv.org_id, dj.ring
    """)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS mttrem_by_ring")
    op.drop_table("tenant_normalization_overrides")
    op.drop_table("software_normalization_log")
    op.drop_table("deployment_jobs")
    op.drop_table("intel_last_good")
    op.drop_table("intel_feed_health")
    op.drop_table("intel_feed_blobs")
    op.drop_table("unpatched_exposures")
    op.drop_table("device_vulnerabilities")
    op.drop_table("remediation_os_targets")
    op.drop_table("remediation_vulnerabilities")
    op.drop_table("remediations")
    op.drop_table("advisory_vulnerabilities")
    op.drop_table("advisories")
    op.drop_table("vulnerability_products")
    op.drop_table("vulnerabilities")
