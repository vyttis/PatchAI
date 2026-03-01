"""Phase 1B: PKI schema — org_cas, enrollment_tokens.

Revision ID: 002_phase_1b
Revises: 001_phase_1a
Create Date: 2026-03-01
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "002_phase_1b"
down_revision: Union[str, None] = "001_phase_1a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- org_cas (envelope-encrypted CA keys — Invariant #7) ---
    op.create_table(
        "org_cas",
        sa.Column(
            "org_id",
            sa.Uuid(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("ca_cert_pem", sa.Text(), nullable=False),
        sa.Column(
            "ca_key_encrypted",
            sa.LargeBinary(),
            nullable=False,
            comment="AES-256-GCM encrypted CA private key. NEVER plaintext.",
        ),
        sa.Column(
            "ca_key_algorithm",
            sa.Text(),
            nullable=False,
            server_default="RSA-4096",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # --- enrollment_tokens (two-part format — Invariant #11) ---
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "token_id",
            sa.Text(),
            unique=True,
            nullable=False,
            comment="Public part of two-part token (~16 chars urlsafe)",
        ),
        sa.Column(
            "token_hash",
            sa.Text(),
            nullable=False,
            comment="bcrypt hash of token_secret (private part)",
        ),
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
        sa.Column("label", sa.Text()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("used_count", sa.Integer(), nullable=False, server_default="0"),
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
    op.create_index(
        "idx_enrollment_tokens_org", "enrollment_tokens", ["org_id"]
    )

    # --- DB role grants (Invariant #7) ---
    # patchpilot_app cannot read ca_key_encrypted; only patchpilot_pki can.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchpilot_app') THEN
                REVOKE SELECT (ca_key_encrypted) ON org_cas FROM patchpilot_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchpilot_pki') THEN
                GRANT SELECT (ca_key_encrypted) ON org_cas TO patchpilot_pki;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.drop_table("enrollment_tokens")
    op.drop_table("org_cas")
