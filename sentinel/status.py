from __future__ import annotations

from typing import Any


def _to_int(val: Any, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _to_float(val: Any, default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def status_iam_access_review(metrics: dict[str, Any]) -> str:
    orphaned_raw = metrics.get("orphaned_accounts")
    days_since = metrics.get("days_since_last_review")

    if days_since is not None and _to_int(days_since) > 90:
        return "red"
    if orphaned_raw is not None:
        orphaned = _to_int(orphaned_raw)
        if orphaned > 7:
            return "red"
        if 3 <= orphaned <= 7:
            return "yellow"

    if orphaned_raw is None or days_since is None:
        return "yellow"
    return "green"


def status_encryption(metrics: dict[str, Any]) -> str:
    total_resources = _to_int(metrics.get("total_confidential_resources"))
    tls_checked = _to_int(metrics.get("tls_endpoints_checked"))
    unencrypted = _to_int(metrics.get("unencrypted_cui_count"))
    weak = _to_int(metrics.get("weak_cipher_endpoints"))
    if unencrypted > 0 or weak > 0:
        return "red"
    if total_resources == 0 or tls_checked == 0:
        return "yellow"
    pending_rotation = _to_int(metrics.get("keys_pending_rotation"))
    if pending_rotation > 0:
        return "yellow"
    return "green"


def status_logging(metrics: dict[str, Any]) -> str:
    coverage_raw = metrics.get("log_coverage_percent")
    gap_raw = metrics.get("max_gap_hours")
    failures = _to_int(metrics.get("critical_control_failures_30d"))

    if failures > 0:
        return "red"
    if coverage_raw is not None and _to_float(coverage_raw) < 90:
        return "red"
    if gap_raw is not None and _to_float(gap_raw) > 24:
        return "red"
    if coverage_raw is None or gap_raw is None:
        return "yellow"
    if _to_float(coverage_raw) < 95:
        return "yellow"
    return "green"


def status_config_mfa(metrics: dict[str, Any]) -> str:
    mfa_raw = metrics.get("mfa_enforcement_percent")
    weak_auth = _to_int(metrics.get("weak_auth_methods"))
    if weak_auth > 0:
        return "red"
    if mfa_raw is None:
        return "yellow"
    if _to_float(mfa_raw) < 100:
        return "red"
    return "green"


def status_change_management(metrics: dict[str, Any]) -> str:
    unapproved_raw = metrics.get("unapproved_changes")
    pending_raw = metrics.get("changes_missing_rollback_test")

    if unapproved_raw is not None and _to_int(unapproved_raw) > 0:
        return "red"
    if pending_raw is not None and _to_int(pending_raw) > 0:
        return "yellow"
    if unapproved_raw is None or pending_raw is None:
        return "yellow"
    return "green"


def status_retention(metrics: dict[str, Any]) -> str:
    overdue_raw = metrics.get("objects_past_retention")
    missing_lifecycle_raw = metrics.get("buckets_missing_lifecycle")

    if overdue_raw is not None and _to_int(overdue_raw) > 0:
        return "red"
    if missing_lifecycle_raw is not None and _to_int(missing_lifecycle_raw) > 0:
        return "yellow"
    if overdue_raw is None and missing_lifecycle_raw is None:
        return "yellow"
    return "green"


def status_generic_pass(metrics: dict[str, Any], key: str = "issues") -> str:
    issues = _to_int(metrics.get(key))
    if issues > 0:
        return "red"
    warnings = _to_int(metrics.get("warnings"))
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
    "A1.2": status_generic_pass,
    "A1.3": status_generic_pass,
}


def resolve_status(control_id: str, metrics: dict[str, Any]) -> str:
    fn = STATUS_BY_CONTROL.get(control_id, status_generic_pass)
    return fn(metrics)
