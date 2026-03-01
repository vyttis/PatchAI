"""Phase 1A: Core schema — organizations, users, departments, devices,
audit_log, deletion_requests, nis2_incidents.

Revision ID: 001_phase_1a
Revises: None
Create Date: 2026-03-01
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from alembic import op

revision: str = "001_phase_1a"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- organizations ---
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("settings", JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False, server_default="viewer"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_email"),
        sa.CheckConstraint(
            "role IN ('org_admin', 'admin', 'viewer')",
            name="ck_users_role",
        ),
    )

    # --- departments ---
    op.create_table(
        "departments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "criticality", sa.Text(), nullable=False, server_default="standard"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # --- devices ---
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "dept_id",
            sa.Uuid(),
            sa.ForeignKey("departments.id", ondelete="SET NULL"),
        ),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("os_build", sa.Text()),
        sa.Column("cert_fingerprint", sa.Text(), unique=True),
        sa.Column("cert_serial", sa.Text()),
        sa.Column("cert_revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "criticality", sa.Text(), nullable=False, server_default="standard"
        ),
        sa.Column("tags", ARRAY(sa.Text())),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column(
            "inventory_section_hashes", JSONB(), nullable=False, server_default="{}"
        ),
        sa.Column("winget_available", sa.Boolean()),
        sa.Column("relay_node_available", sa.Boolean()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # --- audit_log (append-only — Invariant #5) ---
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "device_id",
            sa.Uuid(),
            sa.ForeignKey("devices.id", ondelete="SET NULL"),
        ),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("resource", sa.Text()),
        sa.Column("changes", JSONB()),
        sa.Column("ai_feature", sa.Text()),
        sa.Column("ip_address", sa.Text()),
        sa.Column("result", sa.Text()),
    )

    # --- deletion_requests (GDPR) ---
    op.create_table(
        "deletion_requests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("request_type", sa.Text(), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("export_url", sa.Text()),
    )

    # --- nis2_incidents (NIS2 Article 21) ---
    op.create_table(
        "nis2_incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("affected_systems", JSONB()),
        sa.Column(
            "detected_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "early_warning_due",
            sa.DateTime(timezone=True),
            sa.Computed("detected_at + interval '24 hours'"),
        ),
        sa.Column(
            "notification_due",
            sa.DateTime(timezone=True),
            sa.Computed("detected_at + interval '72 hours'"),
        ),
        sa.Column(
            "final_report_due",
            sa.DateTime(timezone=True),
            sa.Computed("detected_at + interval '3 months'"),
        ),
        sa.Column("early_warning_sent_at", sa.DateTime(timezone=True)),
        sa.Column("notification_sent_at", sa.DateTime(timezone=True)),
        sa.Column("related_cve_ids", ARRAY(sa.Text())),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # --- Compound indexes (tenant isolation + performance) ---
    op.create_index("idx_devices_org", "devices", ["org_id", "id"])
    op.create_index(
        "idx_audit_org_ts",
        "audit_log",
        ["org_id", sa.text("timestamp DESC")],
    )
    op.create_index("idx_users_org", "users", ["org_id", "email"])

    # --- Audit log DB constraint (Invariant #5) ---
    # Revoke UPDATE and DELETE from patchpilot_app role.
    # This runs as raw SQL because Alembic has no built-in REVOKE support.
    # In environments where the role doesn't exist yet (e.g. tests), this is
    # wrapped in a DO block so it doesn't fail.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchpilot_app') THEN
                REVOKE UPDATE, DELETE ON audit_log FROM patchpilot_app;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.drop_table("nis2_incidents")
    op.drop_table("deletion_requests")
    op.drop_table("audit_log")
    op.drop_table("devices")
    op.drop_table("departments")
    op.drop_table("users")
    op.drop_table("organizations")
