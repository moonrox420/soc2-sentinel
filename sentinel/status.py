from __future__ import annotations

from typing import Any


def status_iam_access_review(metrics: dict[str, Any]) -> str:
    orphaned_raw = metrics.get("orphaned_accounts")
    days_since = metrics.get("days_since_last_review")

    if days_since is not None and int(days_since) > 90:
        return "red"
    if orphaned_raw is not None:
        orphaned = int(orphaned_raw)
        if orphaned > 7:
            return "red"
        if 3 <= orphaned <= 7:
            return "yellow"

    if orphaned_raw is None or days_since is None:
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
    coverage_raw = metrics.get("log_coverage_percent")
    gap_raw = metrics.get("max_gap_hours")
    failures = int(metrics.get("critical_control_failures_30d", 0))

    if failures > 0:
        return "red"
    if coverage_raw is not None and float(coverage_raw) < 90:
        return "red"
    if gap_raw is not None and float(gap_raw) > 24:
        return "red"
    if coverage_raw is None or gap_raw is None:
        return "yellow"
    if float(coverage_raw) < 95:
        return "yellow"
    return "green"


def status_config_mfa(metrics: dict[str, Any]) -> str:
    mfa_raw = metrics.get("mfa_enforcement_percent")
    weak_auth = int(metrics.get("weak_auth_methods", 0))
    if weak_auth > 0:
        return "red"
    if mfa_raw is None:
        return "yellow"
    if float(mfa_raw) < 100:
        return "red"
    return "green"


def status_change_management(metrics: dict[str, Any]) -> str:
    unapproved_raw = metrics.get("unapproved_changes")
    pending_raw = metrics.get("changes_missing_rollback_test")

    if unapproved_raw is not None and int(unapproved_raw) > 0:
        return "red"
    if pending_raw is not None and int(pending_raw) > 0:
        return "yellow"
    if unapproved_raw is None or pending_raw is None:
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