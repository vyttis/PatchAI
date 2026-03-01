"""Tests for TenantMixin — tenant isolation guard (Security Invariant #16)."""

import uuid

import pytest

from backend.app.models.base import TenantMixin


def test_validate_org_scope_rejects_none():
    """org_id=None must raise ValueError — cross-org leak prevention."""
    with pytest.raises(ValueError, match="org_id must not be None"):
        TenantMixin._validate_org_scope(None)


def test_validate_org_scope_accepts_valid_uuid():
    """Valid UUID must pass without error."""
    TenantMixin._validate_org_scope(uuid.uuid4())


def test_tenant_mixin_has_org_id_column():
    """TenantMixin must declare org_id as a mapped column."""
    assert hasattr(TenantMixin, "org_id")
    assert hasattr(TenantMixin, "__annotations__")
    assert "org_id" in TenantMixin.__annotations__


def test_tenant_mixin_docstring_mentions_required():
    """Docstring must state that all customer-data models MUST inherit this."""
    assert "MUST" in TenantMixin.__doc__
    assert "Invariant #16" in TenantMixin.__doc__
