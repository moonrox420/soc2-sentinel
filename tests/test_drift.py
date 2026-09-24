from __future__ import annotations

import json
from pathlib import Path

from sentinel.drift import _compare_collector_metrics, detect_configuration_drift


def test_drift_empty_base(tmp_path: Path):
    rep = detect_configuration_drift(tmp_path)
    assert not rep.drift_detected
    assert rep.total_drift_items == 0
    assert rep.items == []
    d = rep.to_dict()
    assert d["drift_detected"] is False


def test_drift_single_run_baseline(tmp_path: Path):
    day1 = tmp_path / "2026-09-20"
    c_dir = day1 / "CC6.2"
    c_dir.mkdir(parents=True)
    payload = {
        "collector": "config_drift",
        "control_id": "CC6.2",
        "provider": "mock",
        "metrics": {
            "open_security_groups": 1,
            "unencrypted_data_stores": 1,
            "orphaned_accounts": 2,
        },
    }
    (c_dir / "evidence.json").write_text(json.dumps(payload), encoding="utf-8")

    rep = detect_configuration_drift(tmp_path, current_date="2026-09-20", record_audit=False)
    assert rep.drift_detected
    assert rep.total_drift_items == 3
    assert any(i.field_name == "open_security_groups" for i in rep.items)


def test_drift_two_runs_comparative(tmp_path: Path):
    # Baseline Day 1: Clean
    day1 = tmp_path / "2026-09-21"
    for col, cid, metrics in [
        ("iam_access_review", "CC6.1", {"orphaned_accounts": 0, "mfa_enforced_percentage": 100.0, "privileged_users": 2}),
        ("config_drift", "CC6.2", {"open_security_groups": 0, "unapproved_changes_detected": 0}),
        ("encryption_status", "C1.2", {"unencrypted_data_stores": 0, "encrypted_at_rest_percentage": 100.0}),
        ("log_aggregator", "CC7.1", {"critical_events_logged_percentage": 100.0}),
        ("resilience_testing", "A1.2", {"successful_backups_24h": 5}),
    ]:
        cdir = day1 / cid
        cdir.mkdir(parents=True)
        (cdir / "evidence.json").write_text(json.dumps({"collector": col, "control_id": cid, "provider": "mock", "metrics": metrics}))

    # Current Day 2: Drifted
    day2 = tmp_path / "2026-09-22"
    for col, cid, metrics in [
        ("iam_access_review", "CC6.1", {"orphaned_accounts": 3, "mfa_enforced_percentage": 85.0, "privileged_users": 5}),
        ("config_drift", "CC6.2", {"open_security_groups": 2, "unapproved_changes_detected": 1}),
        ("encryption_status", "C1.2", {"unencrypted_data_stores": 1, "encrypted_at_rest_percentage": 90.0}),
        ("log_aggregator", "CC7.1", {"critical_events_logged_percentage": 80.0}),
        ("resilience_testing", "A1.2", {"successful_backups_24h": 2}),
    ]:
        cdir = day2 / cid
        cdir.mkdir(parents=True)
        (cdir / "evidence.json").write_text(json.dumps({"collector": col, "control_id": cid, "provider": "mock", "metrics": metrics}))

    rep = detect_configuration_drift(tmp_path, baseline_date="2026-09-21", current_date="2026-09-22", record_audit=True)
    assert rep.drift_detected
    assert rep.total_drift_items >= 8
    criticals = [i for i in rep.items if i.severity == "CRITICAL"]
    assert len(criticals) >= 3  # MFA drop, open SGs, unencrypted stores


def test_compare_collector_metrics_helper():
    items = _compare_collector_metrics("unknown_collector", "X1.1", {}, {}, "2026-09-23T00:00:00Z")
    assert items == []
