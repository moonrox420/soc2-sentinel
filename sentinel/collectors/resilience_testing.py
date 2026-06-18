from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.collectors._helpers import (
    apply_collection_metadata,
    fetch_snapshot,
    log_collection_done,
    write_failure_evidence,
)
from sentinel.config import SentinelConfig
from sentinel.errors import ProviderError
from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import status_generic_pass


def collect_resilience_testing(
    provider: Provider,
    *,
    control_id: str = "A1.2",
    base: Path | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    try:
        snap = fetch_snapshot(provider.resilience_snapshot, collector="resilience_testing")
    except ProviderError as exc:
        return write_failure_evidence(
            control_id=control_id,
            provider_name=provider.name,
            collector="resilience_testing",
            error=str(exc),
            base=base,
            config=cfg,
        )

    issues = 0
    if snap.get("last_restore_test_days_ago", 999) > 90:
        issues += 1
    if not snap.get("failover_test_passed", False):
        issues += 1
    if snap.get("backup_jobs_failed_30d", 0) > 0:
        issues += 1

    metrics = {
        "last_backup_hours_ago": snap.get("last_backup_hours_ago"),
        "last_restore_test_days_ago": snap.get("last_restore_test_days_ago"),
        "rto_target_hours": snap.get("rto_target_hours"),
        "rpo_target_hours": snap.get("rpo_target_hours"),
        "failover_test_days_ago": snap.get("failover_test_days_ago"),
        "failover_test_passed": snap.get("failover_test_passed", False),
        "backup_jobs_success_30d": snap.get("backup_jobs_success_30d", 0),
        "backup_jobs_failed_30d": snap.get("backup_jobs_failed_30d", 0),
        "issues": issues,
    }
    findings = []
    if metrics["last_restore_test_days_ago"] and metrics["last_restore_test_days_ago"] > 90:
        findings.append({"issue": "restore test overdue (>90 days)", "severity": "high"})
    if not metrics["failover_test_passed"]:
        findings.append({"issue": "failover test not passed", "severity": "medium"})

    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": status_generic_pass(metrics),
        "metrics": metrics,
        "evidence_artifacts": [],
        "findings": findings,
        "notes": snap.get("notes", "Backup, restore, and failover resilience evidence for A1.2/A1.3."),
        "provider": provider.name,
    }
    apply_collection_metadata(payload, snap)
    log_collection_done(collector="resilience_testing", provider=provider.name, control_id=control_id, snap=snap)
    return write_evidence(
        payload,
        base=base,
        extra_files={"resilience_report.json": json.dumps(snap, indent=2)},
        config=cfg,
    )