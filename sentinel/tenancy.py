"""Multi-Tenant Isolation and Workspace Context Management."""

from __future__ import annotations

import contextvars
import re
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Generator

from sentinel.errors import ValidationError

# Regex to enforce strict tenant slug format preventing path traversal or special char injection
TENANT_SLUG_REGEX = re.compile(r"^[a-z0-9][a-z0-9\-_]{1,62}[a-z0-9]$")
DEFAULT_TENANT_ID = "default"


@dataclass(frozen=True)
class TenantContext:
    """Immutable context containing active tenant identity, configuration, and storage boundaries."""

    tenant_id: str
    tenant_name: str = ""
    environment: str = "production"
    metadata: dict[str, Any] = field(default_factory=dict)
    key_id: str | None = None

    def __post_init__(self) -> None:
        if self.tenant_id != DEFAULT_TENANT_ID and not TENANT_SLUG_REGEX.match(
            self.tenant_id
        ):
            raise ValidationError(
                f"Invalid tenant_id format '{self.tenant_id}'. Must be 3-64 chars, lowercase alphanumeric with hyphens or underscores."
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Thread-safe contextvar for async and multi-threaded worker tenant propagation
_CURRENT_TENANT: contextvars.ContextVar[TenantContext] = contextvars.ContextVar(
    "current_tenant",
    default=TenantContext(
        tenant_id=DEFAULT_TENANT_ID,
        tenant_name="Default Organization",
        environment="production",
    ),
)


def get_current_tenant() -> TenantContext:
    """Retrieve the currently active tenant context."""
    return _CURRENT_TENANT.get()


def get_current_tenant_id() -> str:
    """Retrieve the slug ID of the currently active tenant."""
    return _CURRENT_TENANT.get().tenant_id


def set_current_tenant(tenant: TenantContext) -> contextvars.Token[TenantContext]:
    """Explicitly set the current tenant context for the executing thread or coroutine."""
    return _CURRENT_TENANT.set(tenant)


def reset_current_tenant(token: contextvars.Token[TenantContext]) -> None:
    """Reset the tenant context back to its previous state using the token."""
    _CURRENT_TENANT.reset(token)


@contextmanager
def tenant_scope(
    tenant_id: str,
    tenant_name: str = "",
    environment: str = "production",
    key_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Generator[TenantContext, None, None]:
    """Context manager for safely executing a code block within an isolated tenant scope."""
    context = TenantContext(
        tenant_id=tenant_id,
        tenant_name=tenant_name or tenant_id,
        environment=environment,
        key_id=key_id,
        metadata=metadata or {},
    )
    token = set_current_tenant(context)
    try:
        yield context
    finally:
        reset_current_tenant(token)


class TenantStorageManager:
    """Manages physical directory paths and data isolation boundaries per tenant."""

    def __init__(self, base_root: Path | None = None) -> None:
        self.base_root = base_root or Path.cwd()

    def get_workspace_dir(self, tenant_id: str | None = None) -> Path:
        """Resolve tenant-isolated root workspace directory."""
        tid = tenant_id or get_current_tenant_id()
        if tid == DEFAULT_TENANT_ID:
            path = self.base_root
        else:
            path = self.base_root / "tenants" / tid
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create_tenant(
        self,
        tenant_id: str,
        tenant_name: str = "",
        environment: str = "production",
        metadata: dict[str, Any] | None = None,
    ) -> TenantContext:
        """Create isolated workspace directories for a new tenant and return context."""
        context = TenantContext(
            tenant_id=tenant_id,
            tenant_name=tenant_name or tenant_id,
            environment=environment,
            metadata=metadata or {},
        )
        self.get_workspace_dir(tenant_id)
        self.get_evidence_root(context)
        self.get_config_dir(context)
        return context

    def get_evidence_root(self, tenant: TenantContext | None = None) -> Path:
        """Resolve tenant-isolated evidence storage directory."""
        t = tenant or get_current_tenant()
        if t.tenant_id == DEFAULT_TENANT_ID:
            path = self.base_root / "evidence"
        else:
            path = self.base_root / "tenants" / t.tenant_id / "evidence"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_audit_log_path(self, tenant: TenantContext | None = None) -> Path:
        """Resolve tenant-isolated audit log file path."""
        t = tenant or get_current_tenant()
        if t.tenant_id == DEFAULT_TENANT_ID:
            return self.base_root / "sentinel-audit.jsonl"
        tenant_dir = self.base_root / "tenants" / t.tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        return tenant_dir / "audit.jsonl"

    def get_config_dir(self, tenant: TenantContext | None = None) -> Path:
        """Resolve tenant-isolated configuration directory."""
        t = tenant or get_current_tenant()
        if t.tenant_id == DEFAULT_TENANT_ID:
            path = self.base_root / "config"
        else:
            path = self.base_root / "tenants" / t.tenant_id / "config"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def list_tenants(self) -> list[str]:
        """Discover all registered or active tenants in local storage."""
        tenants = [DEFAULT_TENANT_ID]
        tenants_root = self.base_root / "tenants"
        if tenants_root.exists() and tenants_root.is_dir():
            for item in tenants_root.iterdir():
                if item.is_dir() and TENANT_SLUG_REGEX.match(item.name):
                    tenants.append(item.name)
        return sorted(list(set(tenants)))
