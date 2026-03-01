"""Base model mixins for PatchPilot ORM models."""

import uuid as _uuid
from datetime import datetime

from sqlalchemy import Uuid, func
from sqlalchemy.orm import Mapped, mapped_column


class TenantMixin:
    """Mixin that enforces tenant isolation on every customer-data table.

    ALL customer-data models MUST inherit this mixin. This is required by
    Security Invariant #16: every customer-data table has org_id NOT NULL,
    every router uses get_org_scope(), every DB query includes
    WHERE org_id = scope.org_id. Cross-org leak = existential incident.
    """

    org_id: Mapped[_uuid.UUID] = mapped_column(
        Uuid,
        nullable=False,
        index=True,
    )

    @classmethod
    def _validate_org_scope(cls, org_id: _uuid.UUID) -> None:
        """Guard: raise if org_id is None. Call before every query."""
        if org_id is None:
            raise ValueError(
                f"{cls.__name__}: org_id must not be None. "
                "Every query requires tenant scoping (Invariant #16)."
            )


class TimestampMixin:
    """Adds created_at column with server-side default."""

    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
