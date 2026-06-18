from __future__ import annotations

from typing import Any


def status_iam_access_review(metrics: dict[str, Any]) -> str:
    orphaned = int(metrics.get("orphaned_accounts", 0))
    days_since = metrics.get("days_since_last_review")
    if days_since is not None and int(days_since) > 90:
        return "red"
    if orphaned > 7:
        return "red"
    if 3 <= orphaned <= 7:
        return "yellow"
    return "green"


def status_encryption(metrics: dict[str, Any]) -> str:
    unencrypted = int(metrics.get("unencrypted_cui_count", 0))
    weak = int(metrics.get("weak_cipher_endpoints", 0))
    if unencrypted > 0 or weak > 0:
        return "red"
    pending_rotation = int(metrics.get("keys_pending_rotation", 0))
    if pending_rotation > 0:
        return "yellow"
    return "green"


def status_logging(metrics: dict[str, Any]) -> str:
    coverage = float(metrics.get("log_coverage_percent", 0))
    gap_hours = float(metrics.get("max_gap_hours", 0))
    failures = int(metrics.get("critical_control_failures_30d", 0))
    if coverage < 90 or gap_hours > 24 or failures > 0:
        return "red"
    if coverage < 95:
        return "yellow"
    return "green"


def status_config_mfa(metrics: dict[str, Any]) -> str:
    mfa_pct = float(metrics.get("mfa_enforcement_percent", 0))
    weak_auth = int(metrics.get("weak_auth_methods", 0))
    if mfa_pct < 100 or weak_auth > 0:
        return "red"
    return "green"


def status_change_management(metrics: dict[str, Any]) -> str:
    unapproved = int(metrics.get("unapproved_changes", 0))
    if unapproved > 0:
        return "red"
    pending = int(metrics.get("changes_missing_rollback_test", 0))
    if pending > 0:
        return "yellow"
    return "green"


def status_retention(metrics: dict[str, Any]) -> str:
    overdue = int(metrics.get("objects_past_retention", 0))
    if overdue > 0:
        return "red"
    return "green"


def status_generic_pass(metrics: dict[str, Any], key: str = "issues") -> str:
    issues = int(metrics.get(key, 0))
    if issues > 0:
        return "red"
    warnings = int(metrics.get("warnings", 0))
    if warnings > 0:
        return "yellow"
    return "green"


STATUS_BY_CONTROL = {
    "CC6.1": status_iam_access_review,
    "CC6.3": status_iam_access_review,
    "C1.1": status_encryption,
    "C1.2": status_encryption,
    "CC6.2": status_config_mfa,
    "CC7.1": status_logging,
    "CC7.2": status_logging,
    "CC8.1": status_change_management,
    "C1.3": status_generic_pass,
    "C1.4": status_retention,
    "A1.3": status_generic_pass,
}


def resolve_status(control_id: str, metrics: dict[str, Any]) -> str:
    fn = STATUS_BY_CONTROL.get(control_id, status_generic_pass)
    return fn(metrics)