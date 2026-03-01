"""Phase 1D: Agent versions table for deployment pack generation.

Revision ID: 003_phase_1d
Revises: 002_phase_1b
Create Date: 2026-03-01
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "003_phase_1d"
down_revision: Union[str, None] = "002_phase_1b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_versions",
        sa.Column(
            "version",
            sa.Text(),
            primary_key=True,
            comment="Semver, e.g. '1.0.0'",
        ),
        sa.Column("windows_msi_url", sa.Text()),
        sa.Column("windows_sha256", sa.Text()),
        sa.Column("windows_sig_url", sa.Text()),
        sa.Column("release_notes", sa.Text()),
        sa.Column(
            "released_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "is_latest",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("minimum_supported_version", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("agent_versions")
