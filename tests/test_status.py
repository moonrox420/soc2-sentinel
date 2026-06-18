from sentinel.status import (
    resolve_status,
    status_change_management,
    status_config_mfa,
    status_encryption,
    status_generic_pass,
    status_iam_access_review,
    status_logging,
    status_retention,
)


def test_iam_status_red_orphaned():
    assert status_iam_access_review({"orphaned_accounts": 10}) == "red"
    assert status_iam_access_review({"orphaned_accounts": 5}) == "yellow"
    assert status_iam_access_review({"orphaned_accounts": 0, "days_since_last_review": 100}) == "red"


def test_encryption_status():
    assert status_encryption({"unencrypted_cui_count": 1}) == "red"
    assert status_encryption({"keys_pending_rotation": 2}) == "yellow"
    assert status_encryption({"unencrypted_cui_count": 0, "weak_cipher_endpoints": 0}) == "green"


def test_logging_status():
    assert status_logging({"log_coverage_percent": 80}) == "red"
    assert status_logging({"log_coverage_percent": 92, "max_gap_hours": 0, "critical_control_failures_30d": 0}) == "yellow"
    assert status_logging({"log_coverage_percent": 98, "max_gap_hours": 0, "critical_control_failures_30d": 0}) == "green"


def test_config_and_change():
    assert status_config_mfa({"mfa_enforcement_percent": 50}) == "red"
    assert status_change_management({"unapproved_changes": 1}) == "red"
    assert status_change_management({"changes_missing_rollback_test": 1}) == "yellow"


def test_retention_and_generic():
    assert status_retention({"objects_past_retention": 1}) == "red"
    assert status_generic_pass({"issues": 0, "warnings": 1}) == "yellow"
    assert resolve_status("CC6.1", {"orphaned_accounts": 0, "days_since_last_review": 10}) == "green"