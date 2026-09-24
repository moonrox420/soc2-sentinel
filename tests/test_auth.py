"""Unit tests for 5-Tier RBAC, Permissions, and Token Management."""

import pytest

from sentinel.auth import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    TokenManager,
    UserIdentity,
    assert_permission,
    auth_scope,
    get_current_user,
)


def test_role_hierarchy_and_permissions() -> None:
    # Super admin must possess all 11 permissions
    assert len(ROLE_PERMISSIONS[Role.SUPER_ADMIN]) == len(Permission)

    # Auditor must only possess read permissions
    auditor_perms = ROLE_PERMISSIONS[Role.AUDITOR]
    assert Permission.READ_EVIDENCE in auditor_perms
    assert Permission.READ_REPORT in auditor_perms
    assert Permission.TRIGGER_COLLECTION not in auditor_perms
    assert Permission.MANAGE_USER not in auditor_perms
    assert Permission.MANAGE_TENANT not in auditor_perms


def test_user_identity_permissions() -> None:
    admin = UserIdentity(user_id="alice", role=Role.SUPER_ADMIN)
    assert admin.has_permission(Permission.MANAGE_TENANT)
    assert admin.has_permission(Permission.RUN_POLICY)

    auditor = UserIdentity(user_id="bob", role=Role.AUDITOR)
    assert auditor.has_permission(Permission.READ_EVIDENCE)
    assert not auditor.has_permission(Permission.MANAGE_TENANT)

    # Anonymous user defaults to least-privilege read-only VIEWER
    anon = UserIdentity.anonymous()
    assert anon.role == Role.VIEWER
    assert anon.has_permission(Permission.READ_EVIDENCE)
    assert anon.has_permission(Permission.READ_REPORT)
    assert not anon.has_permission(Permission.TRIGGER_COLLECTION)
    assert not anon.has_permission(Permission.MANAGE_TENANT)
    assert not anon.has_permission(Permission.MANAGE_CREDENTIALS)


def test_auth_scope_and_assertion() -> None:
    auditor = UserIdentity(user_id="bob", role=Role.AUDITOR)
    admin = UserIdentity(user_id="alice", role=Role.SUPER_ADMIN)

    with auth_scope(auditor):
        assert get_current_user().user_id == "bob"
        assert_permission(Permission.READ_EVIDENCE)
        with pytest.raises(PermissionError, match="Permission denied"):
            assert_permission(Permission.MANAGE_TENANT)

        with auth_scope(admin):
            assert get_current_user().user_id == "alice"
            assert_permission(Permission.MANAGE_TENANT)

        assert get_current_user().user_id == "bob"


def test_token_manager_signing_and_verification() -> None:
    user = UserIdentity(user_id="charlie", role=Role.SECURITY_ADMIN, tenant_id="acme")
    token = TokenManager.create_token(user, expires_in_seconds=3600)
    assert isinstance(token, str)
    assert "." in token

    # Verify valid token
    verified = TokenManager.verify_token(token)
    assert verified is not None
    assert verified.user_id == "charlie"
    assert verified.role == Role.SECURITY_ADMIN
    assert verified.tenant_id == "acme"

    # Tampered token
    tampered = token[:-4] + "abcd"
    assert TokenManager.verify_token(tampered) is None

    # Malformed token
    assert TokenManager.verify_token("not-a-token") is None
    assert TokenManager.verify_token("") is None


def test_token_manager_expiration() -> None:
    user = UserIdentity(user_id="dan", role=Role.SYSTEM_USER)
    # Expired token (negative lifespan)
    token = TokenManager.create_token(user, expires_in_seconds=-10)
    assert TokenManager.verify_token(token) is None
