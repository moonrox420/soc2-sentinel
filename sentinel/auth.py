"""Enterprise 5-Tier RBAC, Permissions Matrix, and Token Authentication."""

from __future__ import annotations

import base64
import contextvars
import enum
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Optional

from sentinel.errors import SentinelError


class Role(str, enum.Enum):
    """Enterprise RBAC roles."""

    SUPER_ADMIN = "super_admin"
    SECURITY_ADMIN = "security_admin"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    SYSTEM_USER = "system_user"
    VIEWER = "viewer"


class Permission(str, enum.Enum):
    """Granular capabilities enforced across API and CLI boundaries."""

    READ_EVIDENCE = "read_evidence"
    READ_REPORT = "read_report"
    READ_CONFIG = "read_config"
    READ_POLICY = "read_policy"
    READ_AUDIT = "read_audit"
    TRIGGER_COLLECTION = "trigger_collection"
    EXPORT_AUDIT_PACK = "export_audit_pack"
    MANAGE_CREDENTIALS = "manage_credentials"
    MANAGE_TENANT = "manage_tenant"
    MANAGE_USER = "manage_user"
    RUN_POLICY = "run_policy"
    TOKEN_MANAGE = "token_manage"
    VERIFY_INTEGRITY = "verify_integrity"


# Canonical permission matrices per role
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.SUPER_ADMIN: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
        Permission.READ_CONFIG,
        Permission.READ_POLICY,
        Permission.READ_AUDIT,
        Permission.TRIGGER_COLLECTION,
        Permission.EXPORT_AUDIT_PACK,
        Permission.MANAGE_CREDENTIALS,
        Permission.MANAGE_TENANT,
        Permission.MANAGE_USER,
        Permission.RUN_POLICY,
        Permission.TOKEN_MANAGE,
        Permission.VERIFY_INTEGRITY,
    },
    Role.SECURITY_ADMIN: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
        Permission.READ_CONFIG,
        Permission.READ_POLICY,
        Permission.READ_AUDIT,
        Permission.TRIGGER_COLLECTION,
        Permission.EXPORT_AUDIT_PACK,
        Permission.MANAGE_CREDENTIALS,
        Permission.RUN_POLICY,
        Permission.VERIFY_INTEGRITY,
    },
    Role.COMPLIANCE_OFFICER: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
        Permission.READ_CONFIG,
        Permission.READ_POLICY,
        Permission.READ_AUDIT,
        Permission.TRIGGER_COLLECTION,
        Permission.EXPORT_AUDIT_PACK,
        Permission.RUN_POLICY,
        Permission.VERIFY_INTEGRITY,
    },
    Role.AUDITOR: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
        Permission.READ_POLICY,
        Permission.READ_AUDIT,
        Permission.VERIFY_INTEGRITY,
    },
    Role.SYSTEM_USER: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
    },
    Role.VIEWER: {
        Permission.READ_EVIDENCE,
        Permission.READ_REPORT,
    },
}


class AuthError(SentinelError, PermissionError):
    """Raised when authentication or authorization checks fail."""

    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class UserIdentity:
    """Authenticated user context."""

    user_id: str
    role: Role = Role.SYSTEM_USER
    email: str = ""
    tenant_id: str = "default"
    is_service_account: bool = False
    session_id: str = field(default_factory=lambda: secrets.token_hex(8))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.email:
            object.__setattr__(self, "email", f"{self.user_id}@sentinel.local")

    def has_permission(self, permission: Permission) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, set())
        return permission in allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role.name,
            "email": self.email,
            "tenant_id": self.tenant_id,
            "is_service_account": self.is_service_account,
        }

    @classmethod
    def anonymous(cls, tenant_id: str = "default") -> UserIdentity:
        return cls(
            user_id="anonymous",
            role=Role.VIEWER,
            email="anonymous@sentinel.local",
            tenant_id=tenant_id,
        )


# Default unauthenticated/system identity (least-privilege read-only)
DEFAULT_ANONYMOUS_USER = UserIdentity.anonymous()

_CURRENT_USER: contextvars.ContextVar[UserIdentity] = contextvars.ContextVar(
    "current_user", default=DEFAULT_ANONYMOUS_USER
)


def get_current_user() -> UserIdentity:
    """Retrieve the currently authenticated user identity."""
    return _CURRENT_USER.get()


def set_current_user(user: UserIdentity) -> contextvars.Token[UserIdentity]:
    """Set the active user identity for the current execution context."""
    return _CURRENT_USER.set(user)


def reset_current_user(token: contextvars.Token[UserIdentity]) -> None:
    """Reset the user context."""
    _CURRENT_USER.reset(token)


@contextmanager
def auth_scope(user: UserIdentity) -> Generator[UserIdentity, None, None]:
    """Scoped execution under a specific user identity."""
    token = set_current_user(user)
    try:
        yield user
    finally:
        reset_current_user(token)


def assert_permission(permission: Permission, user: UserIdentity | None = None) -> None:
    """Assert that the given or current user has the required permission."""
    u = user or get_current_user()
    if not u.has_permission(permission):
        raise AuthError(
            f"Permission denied: User '{u.user_id}' with role '{u.role.name}' lacks permission '{permission.name}'"
        )


class TokenManager:
    """Issues and validates cryptographically signed session tokens and API keys."""

    _EPHEMERAL_SECRET: Optional[str] = None

    @classmethod
    def get_signing_secret(cls, explicit_secret: Optional[str] = None) -> str:
        """Resolve active signing secret from argument, environment, or cryptographically secure runtime secret."""
        if explicit_secret:
            return explicit_secret
        env_secret = os.getenv("SENTINEL_AUTH_SECRET")
        if env_secret:
            return env_secret
        if cls._EPHEMERAL_SECRET is None:
            cls._EPHEMERAL_SECRET = secrets.token_hex(32)
        return cls._EPHEMERAL_SECRET

    @classmethod
    def create_token(
        cls,
        user: UserIdentity,
        expires_in_seconds: int = 86400,
        secret: Optional[str] = None,
    ) -> str:
        """Create a signed HMAC token containing user claims."""
        signing_key = cls.get_signing_secret(secret).encode("utf-8")
        payload = {
            "uid": user.user_id,
            "email": user.email,
            "role": user.role.name,
            "tid": user.tenant_id,
            "sa": user.is_service_account,
            "exp": int(time.time()) + expires_in_seconds,
            "nonce": secrets.token_hex(6),
        }
        raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        raw_bytes = raw_json.encode("utf-8")
        sig = hmac.new(signing_key, raw_bytes, hashlib.sha256).hexdigest()
        b64_payload = base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")
        return f"sentinel_{b64_payload}.{sig}"

    @classmethod
    def verify_token(
        cls, token: str, secret: Optional[str] = None
    ) -> Optional[UserIdentity]:
        """Validate signature and extract authenticated UserIdentity, or return None."""
        if not token or not token.startswith("sentinel_") or "." not in token:
            return None

        signing_key = cls.get_signing_secret(secret).encode("utf-8")
        token_body = token[len("sentinel_") :]
        b64_payload, signature = token_body.split(".", 1)

        pad = "=" * ((4 - len(b64_payload) % 4) % 4)
        try:
            raw_bytes = base64.urlsafe_b64decode(b64_payload + pad)
            expected_sig = hmac.new(signing_key, raw_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, signature):
                return None

            payload = json.loads(raw_bytes.decode("utf-8"))
            if payload.get("exp", 0) < time.time():
                return None

            role = getattr(Role, payload["role"])
            return UserIdentity(
                user_id=payload["uid"],
                role=role,
                email=payload.get("email", ""),
                tenant_id=payload.get("tid", "default"),
                is_service_account=bool(payload.get("sa", False)),
            )
        except Exception:
            return None
