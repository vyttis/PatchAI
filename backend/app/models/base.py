"""Base model mixins for PatchPilot ORM models."""

import uuid

from sqlalchemy import Column, text
from sqlalchemy.dialects.postgresql import UUID


class TenantMixin:
    """Mixin that enforces tenant isolation on every customer-data table.

    Every table inheriting this mixin will have an org_id NOT NULL column.
    Every query MUST include WHERE org_id = scope.org_id.
    Cross-org leak = existential incident. (Invariant #16)
    """

    org_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        server_default=text("gen_random_uuid()"),
        comment="Tenant isolation key — every query must filter on this",
    )

    @classmethod
    def _validate_org_scope(cls, org_id: uuid.UUID) -> None:
        """Guard: raise if org_id is None. Call before every query."""
        if org_id is None:
            raise ValueError(
                f"{cls.__name__}: org_id must not be None. "
                "Every query requires tenant scoping (Invariant #16)."
            )
