from __future__ import annotations

import json
from pathlib import Path

from sentinel.scoring import (
    _eval_config_drift,
    _eval_encryption,
    _eval_iam,
    _eval_logging,
    _eval_resilience,
    _eval_retention,
    _eval_zero_trust,
    _safe_float,
    _safe_int,
    compute_compliance_scorecard,
)


def test_safe_conversions():
    assert _safe_float("12.5") == 12.5
    assert _safe_float(None, 3.0) == 3.0
    assert _safe_float("invalid", 4.0) == 4.0

    assert _safe_int("42") == 42
    assert _safe_int(None, 5) == 5
    assert _safe_int("invalid", 10) == 10


def test_eval_iam_none():
    res = _eval_iam(None)
    assert res.status == "NOT_ASSESSED"
    assert res.score == 0.0
    assert len(res.findings) > 0


def test_eval_iam_perfect_and_deficient():
    perfect = {
        "metrics": {
            "orphaned_accounts": 0,
            "mfa_enforced_percentage": 100.0,
            "days_since_last_review": 30,
        },
        "collection_quality": "complete",
    }
    p_res = _eval_iam(perfect)
    assert p_res.status == "PASS"
    assert p_res.score == 100.0
    assert len(p_res.findings) == 0

    deficient = {
        "metrics": {
            "orphaned_accounts": 5,
            "mfa_enforced_percentage": 60.0,
            "days_since_last_review": 120,
        },
        "collection_quality": "partial",
    }
    d_res = _eval_iam(deficient)
    assert d_res.status in {"PARTIAL", "FAIL"}
    assert d_res.score < 60.0
    assert len(d_res.findings) == 3


def test_eval_logging_none_and_values():
    assert _eval_logging(None).status == "NOT_ASSESSED"

    good = {
        "metrics": {
            "log_streams_active": 4,
            "critical_events_logged_percentage": 99.0,
            "retention_days": 365,
            "longest_gap_hours": 0.5,
        },
        "collection_quality": "complete",
    }
    res = _eval_logging(good)
    assert res.status == "PASS"
    assert res.score == 100.0

    bad = {
        "metrics": {
            "log_streams_active": 0,
            "critical_events_logged_percentage": 80.0,
            "retention_days": 90,
            "longest_gap_hours": 48.0,
        }
    }
    b_res = _eval_logging(bad)
    assert b_res.status == "FAIL"
    assert len(b_res.findings) >= 3


def test_eval_config_drift():
    assert _eval_config_drift(None).status == "NOT_ASSESSED"

    clean = {
        "metrics": {
            "resources_evaluated": 50,
            "drifted_resources": 0,
            "open_security_groups": 0,
            "unapproved_changes_detected": 0,
        }
    }
    assert _eval_config_drift(clean).status == "PASS"

    drifted = {
        "metrics": {
            "resources_evaluated": 50,
            "drifted_resources": 20,
            "open_security_groups": 2,
            "unapproved_changes_detected": 1,
        }
    }
    d_res = _eval_config_drift(drifted)
    assert d_res.status in {"PARTIAL", "FAIL"}
    assert len(d_res.findings) >= 3


def test_eval_encryption():
    assert _eval_encryption(None).status == "NOT_ASSESSED"

    full = {
        "metrics": {
            "encrypted_at_rest_percentage": 100.0,
            "tls_enforced_percentage": 100.0,
            "unencrypted_data_stores": 0,
            "fips_compliant_algorithms": True,
        }
    }
    assert _eval_encryption(full).status == "PASS"

    unenc = {
        "metrics": {
            "encrypted_at_rest_percentage": 70.0,
            "tls_enforced_percentage": 80.0,
            "unencrypted_data_stores": 3,
            "fips_compliant_algorithms": False,
        }
    }
    u_res = _eval_encryption(unenc)
    assert u_res.status == "FAIL"
    assert len(u_res.findings) >= 3


def test_eval_retention():
    assert _eval_retention(None).status == "NOT_ASSESSED"

    valid = {
        "metrics": {
            "policies_checked": 10,
            "compliant_buckets": 10,
            "deletion_certificates_valid": True,
        }
    }
    assert _eval_retention(valid).status == "PASS"

    invalid = {
        "metrics": {
            "policies_checked": 10,
            "compliant_buckets": 5,
            "deletion_certificates_valid": False,
        }
    }
    inv_res = _eval_retention(invalid)
    assert inv_res.score < 50.0


def test_eval_resilience():
    assert _eval_resilience(None).status == "NOT_ASSESSED"

    ok = {
        "metrics": {
            "backup_jobs_evaluated": 5,
            "successful_backups_24h": 5,
            "restore_tested_90d": True,
            "rto_target_met": True,
            "rpo_target_met": True,
        }
    }
    assert _eval_resilience(ok).status == "PASS"

    failing = {
        "metrics": {
            "backup_jobs_evaluated": 5,
            "successful_backups_24h": 2,
            "restore_tested_90d": False,
            "rto_target_met": False,
            "rpo_target_met": False,
        }
    }
    f_res = _eval_resilience(failing)
    assert f_res.score < 50.0


def test_eval_zero_trust():
    assert _eval_zero_trust(None).status == "NOT_ASSESSED"

    full_zt = {
        "metrics": {
            "identity_verified": True,
            "device_health_checked": True,
            "least_privilege_enforced": True,
            "continuous_monitoring_active": True,
        }
    }
    assert _eval_zero_trust(full_zt).score == 100.0

    raw_zt = {
        "metrics": {
            "identity_verified": False,
            "device_health_checked": False,
            "least_privilege_enforced": False,
            "continuous_monitoring_active": False,
            "zt_maturity_score": 3.0,
        }
    }
    assert _eval_zero_trust(raw_zt).score == 75.0


def test_compute_compliance_scorecard_empty(tmp_path: Path):
    scorecard = compute_compliance_scorecard(tmp_path)
    assert scorecard.overall_posture_score == 0.0
    assert scorecard.soc2.controls_evaluated == 7
    assert scorecard.soc2.controls_passed == 0
    d = scorecard.to_dict()
    assert "overall_posture_score" in d
    assert "soc2" in d


def test_compute_compliance_scorecard_with_evidence(tmp_path: Path):
    day_dir = tmp_path / "2026-09-23"
    ctrl_dir = day_dir / "CC6.1"
    ctrl_dir.mkdir(parents=True)
    payload = {
        "collector": "iam_access_review",
        "control_id": "CC6.1",
        "provider": "mock",
        "collection_quality": "complete",
        "metrics": {
            "orphaned_accounts": 0,
            "mfa_enforced_percentage": 100.0,
            "days_since_last_review": 15,
        },
    }
    (ctrl_dir / "evidence.json").write_text(json.dumps(payload), encoding="utf-8")

    scorecard = compute_compliance_scorecard(tmp_path, date_str="2026-09-23")
    assert scorecard.provider == "mock"
    assert scorecard.overall_posture_score > 0.0
    iam_ctrl = [c for c in scorecard.controls if c.control_id == "CC6.1"][0]
    assert iam_ctrl.status == "PASS"
    assert iam_ctrl.score == 100.0
