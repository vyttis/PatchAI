"""Tests for TenantMixin — tenant isolation guard (Security Invariant #16)."""

import pytest

from backend.app.models.base import TenantMixin


class FakeModel(TenantMixin):
    __name__ = "FakeModel"


def test_validate_org_scope_rejects_none():
    """org_id=None must raise ValueError — cross-org leak prevention."""
    with pytest.raises(ValueError, match="org_id must not be None"):
        FakeModel._validate_org_scope(None)


def test_validate_org_scope_accepts_valid_uuid():
    """Valid UUID must pass without error."""
    import uuid

    FakeModel._validate_org_scope(uuid.uuid4())
