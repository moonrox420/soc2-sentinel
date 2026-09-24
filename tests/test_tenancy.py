"""Unit tests for Multi-Tenant Isolation and Storage."""

from pathlib import Path

import pytest

from sentinel.errors import ValidationError
from sentinel.tenancy import (
    TenantContext,
    TenantStorageManager,
    get_current_tenant_id,
    tenant_scope,
)


def test_tenant_context_structure() -> None:
    ctx = TenantContext("acme-corp", "Acme Corporation")
    assert ctx.tenant_id == "acme-corp"
    assert ctx.tenant_name == "Acme Corporation"
    d = ctx.to_dict()
    assert d["tenant_id"] == "acme-corp"
    assert d["tenant_name"] == "Acme Corporation"


def test_tenant_scope_propagation() -> None:
    assert get_current_tenant_id() == "default"

    with tenant_scope("tenant-alpha"):
        assert get_current_tenant_id() == "tenant-alpha"
        with tenant_scope("tenant-beta"):
            assert get_current_tenant_id() == "tenant-beta"
        assert get_current_tenant_id() == "tenant-alpha"

    assert get_current_tenant_id() == "default"


def test_tenant_storage_manager_creation_and_listing(tmp_path: Path) -> None:
    mgr = TenantStorageManager(tmp_path)
    assert "default" in mgr.list_tenants()

    t1 = mgr.create_tenant("org-finance")
    assert t1.tenant_id == "org-finance"
    assert mgr.get_evidence_root(t1).exists()
    assert mgr.get_config_dir(t1).exists()
    assert mgr.get_audit_log_path(t1).name == "audit.jsonl"

    tenants = mgr.list_tenants()
    assert "org-finance" in tenants
    assert "default" in tenants

    # Default paths
    default_ev = mgr.get_evidence_root()
    assert default_ev == tmp_path / "evidence"
    default_audit = mgr.get_audit_log_path()
    assert default_audit == tmp_path / "sentinel-audit.jsonl"


def test_tenant_storage_manager_slug_validation(tmp_path: Path) -> None:
    mgr = TenantStorageManager(tmp_path)

    invalid_slugs = [
        "../traversal",
        "/absolute/path",
        "invalid slug with spaces",
        "UPPERCASE",
        "a",  # too short
        "-starts-with-dash",
        "ends-with-dash-",
        "special@char",
    ]

    for bad_slug in invalid_slugs:
        with pytest.raises(ValidationError, match="Invalid tenant_id format"):
            mgr.create_tenant(bad_slug)
