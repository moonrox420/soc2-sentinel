from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.audit import append_audit_event

logger = logging.getLogger("sentinel.drift")


@dataclass
class DriftItem:
    collector: str
    control_id: str
    field_name: str
    baseline_value: Any
    current_value: Any
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DriftReport:
    timestamp: str
    provider: str
    baseline_date: str | None
    current_date: str
    drift_detected: bool
    total_drift_items: int
    items: list[DriftItem]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "provider": self.provider,
            "baseline_date": self.baseline_date,
            "current_date": self.current_date,
            "drift_detected": self.drift_detected,
            "total_drift_items": self.total_drift_items,
            "items": [item.to_dict() for item in self.items],
        }


def _load_run_evidence(date_dir: Path | None) -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    if not date_dir or not date_dir.exists() or not date_dir.is_dir():
        return evidence
    canonical_map = {
        "CC6.1": "iam_access_review",
        "CC6.2": "config_drift",
        "CC7.1": "log_aggregator",
        "C1.2": "encryption_status",
        "C1.4": "retention_check",
        "A1.2": "resilience_testing",
        "ZT-1": "zt_continuous_verification",
    }
    for sub in date_dir.iterdir():
        if not sub.is_dir() or sub.name == "manifests":
            continue
        ev_file = sub / "report.json"
        if not ev_file.exists():
            ev_file = sub / "evidence.json"
        if ev_file.exists():
            try:
                data = json.loads(ev_file.read_text(encoding="utf-8"))
                collector = (
                    data.get("collector")
                    or canonical_map.get(data.get("control_id", ""))
                    or canonical_map.get(sub.name)
                    or data.get("control_id")
                    or sub.name
                )
                evidence[collector] = data
                ctrl_id = data.get("control_id")
                if ctrl_id and ctrl_id in canonical_map:
                    evidence[canonical_map[ctrl_id]] = data
            except Exception as exc:
                logger.debug("Failed reading evidence at %s: %s", ev_file, exc)
    return evidence


def _compare_collector_metrics(
    collector: str,
    control_id: str,
    base_metrics: dict[str, Any],
    curr_metrics: dict[str, Any],
    now_iso: str,
) -> list[DriftItem]:
    items: list[DriftItem] = []

    # 1. IAM Drift
    if collector in {"iam_access_review", "CC6.1"}:
        old_orphaned = base_metrics.get("orphaned_accounts", 0)
        new_orphaned = curr_metrics.get("orphaned_accounts", 0)
        if new_orphaned > old_orphaned:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="orphaned_accounts",
                    baseline_value=old_orphaned,
                    current_value=new_orphaned,
                    severity="HIGH",
                    description=f"Orphaned accounts increased from {old_orphaned} to {new_orphaned}",
                    timestamp=now_iso,
                )
            )

        old_mfa = base_metrics.get(
            "mfa_enforced_percentage",
            base_metrics.get("mfa_enforcement_percent", 100.0),
        )
        new_mfa = curr_metrics.get(
            "mfa_enforced_percentage",
            curr_metrics.get("mfa_enforcement_percent", 100.0),
        )
        if new_mfa < old_mfa:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="mfa_enforced_percentage",
                    baseline_value=old_mfa,
                    current_value=new_mfa,
                    severity="CRITICAL",
                    description=f"MFA enforcement dropped from {old_mfa:.1f}% to {new_mfa:.1f}%",
                    timestamp=now_iso,
                )
            )

        old_priv = base_metrics.get(
            "privileged_users", base_metrics.get("privileged_count", 0)
        )
        new_priv = curr_metrics.get(
            "privileged_users", curr_metrics.get("privileged_count", 0)
        )
        if new_priv > old_priv:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="privileged_users",
                    baseline_value=old_priv,
                    current_value=new_priv,
                    severity="MEDIUM",
                    description=f"Privileged user count increased from {old_priv} to {new_priv}",
                    timestamp=now_iso,
                )
            )

    # 2. Config Drift
    elif collector in {"config_drift", "CC6.2"}:
        old_open_sgs = base_metrics.get(
            "open_security_groups", base_metrics.get("open_http_listeners", 0)
        )
        new_open_sgs = curr_metrics.get(
            "open_security_groups", curr_metrics.get("open_http_listeners", 0)
        )
        if new_open_sgs > old_open_sgs:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="open_security_groups",
                    baseline_value=old_open_sgs,
                    current_value=new_open_sgs,
                    severity="CRITICAL",
                    description=f"Open security groups with 0.0.0.0/0 ingress increased from {old_open_sgs} to {new_open_sgs}",
                    timestamp=now_iso,
                )
            )

        old_unapproved = base_metrics.get(
            "unapproved_changes_detected", base_metrics.get("unapproved_changes", 0)
        )
        new_unapproved = curr_metrics.get(
            "unapproved_changes_detected", curr_metrics.get("unapproved_changes", 0)
        )
        if new_unapproved > old_unapproved:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="unapproved_changes_detected",
                    baseline_value=old_unapproved,
                    current_value=new_unapproved,
                    severity="HIGH",
                    description=f"Unapproved configuration changes increased from {old_unapproved} to {new_unapproved}",
                    timestamp=now_iso,
                )
            )

    # 3. Encryption Drift
    elif collector in {"encryption_status", "C1.2"}:
        old_unenc = base_metrics.get(
            "unencrypted_data_stores", base_metrics.get("unencrypted_cui_count", 0)
        )
        new_unenc = curr_metrics.get(
            "unencrypted_data_stores", curr_metrics.get("unencrypted_cui_count", 0)
        )
        if new_unenc > old_unenc:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="unencrypted_data_stores",
                    baseline_value=old_unenc,
                    current_value=new_unenc,
                    severity="CRITICAL",
                    description=f"Unencrypted data stores increased from {old_unenc} to {new_unenc}",
                    timestamp=now_iso,
                )
            )

        old_rest = base_metrics.get("encrypted_at_rest_percentage", 100.0)
        new_rest = curr_metrics.get("encrypted_at_rest_percentage", 100.0)
        if new_rest < old_rest:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="encrypted_at_rest_percentage",
                    baseline_value=old_rest,
                    current_value=new_rest,
                    severity="HIGH",
                    description=f"Encryption at rest dropped from {old_rest:.1f}% to {new_rest:.1f}%",
                    timestamp=now_iso,
                )
            )

    # 4. Logging Drift
    elif collector in {"log_aggregator", "CC7.1"}:
        old_comp = base_metrics.get(
            "critical_events_logged_percentage",
            base_metrics.get("log_coverage_percent", 100.0),
        )
        new_comp = curr_metrics.get(
            "critical_events_logged_percentage",
            curr_metrics.get("log_coverage_percent", 100.0),
        )
        if new_comp < old_comp:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="critical_events_logged_percentage",
                    baseline_value=old_comp,
                    current_value=new_comp,
                    severity="HIGH",
                    description=f"Log completeness dropped from {old_comp:.1f}% to {new_comp:.1f}%",
                    timestamp=now_iso,
                )
            )

    # 5. Resilience Drift
    elif collector in {"resilience_testing", "A1.2"}:
        old_backups = base_metrics.get(
            "successful_backups_24h", base_metrics.get("backup_jobs_success_30d", 0)
        )
        new_backups = curr_metrics.get(
            "successful_backups_24h", curr_metrics.get("backup_jobs_success_30d", 0)
        )
        if new_backups < old_backups:
            items.append(
                DriftItem(
                    collector=collector,
                    control_id=control_id,
                    field_name="successful_backups_24h",
                    baseline_value=old_backups,
                    current_value=new_backups,
                    severity="HIGH",
                    description=f"Successful backups in 24h dropped from {old_backups} to {new_backups}",
                    timestamp=now_iso,
                )
            )

    return items


def detect_configuration_drift(
    evidence_base: Path | None = None,
    *,
    baseline_date: str | None = None,
    current_date: str | None = None,
    record_audit: bool = True,
) -> DriftReport:
    """Compare evidence between two dates (or the two latest runs) to detect compliance drift."""
    base = evidence_base or (Path.cwd() / "evidence")
    now_iso = datetime.now(timezone.utc).isoformat()

    if not base.exists():
        return DriftReport(
            timestamp=now_iso,
            provider="unknown",
            baseline_date=None,
            current_date="none",
            drift_detected=False,
            total_drift_items=0,
            items=[],
        )

    dirs = sorted(
        [d for d in base.iterdir() if d.is_dir() and d.name != "manifests"],
        key=lambda d: d.name,
    )
    if not dirs:
        return DriftReport(
            timestamp=now_iso,
            provider="unknown",
            baseline_date=None,
            current_date="none",
            drift_detected=False,
            total_drift_items=0,
            items=[],
        )

    if current_date:
        cur_dirs = [d for d in dirs if d.name == current_date]
        cur_dir = cur_dirs[0] if cur_dirs else dirs[-1]
    else:
        cur_dir = dirs[-1]

    if baseline_date:
        base_dirs = [d for d in dirs if d.name == baseline_date]
        base_dir = base_dirs[0] if base_dirs else (dirs[-2] if len(dirs) >= 2 else None)
    else:
        # Default baseline is previous run if exists
        other_dirs = [d for d in dirs if d.name != cur_dir.name]
        base_dir = other_dirs[-1] if other_dirs else None

    current_evidence = _load_run_evidence(cur_dir)
    baseline_evidence = _load_run_evidence(base_dir) if base_dir else {}

    provider = "unknown"
    for ev in current_evidence.values():
        if ev.get("provider"):
            provider = ev["provider"]
            break

    drift_items: list[DriftItem] = []

    if baseline_evidence:
        for collector, cur_payload in current_evidence.items():
            base_payload = baseline_evidence.get(collector)
            if not base_payload:
                continue
            ctrl_id = cur_payload.get("control_id", "UNKNOWN")
            cur_metrics = cur_payload.get("metrics", {})
            base_metrics = base_payload.get("metrics", {})
            items = _compare_collector_metrics(
                collector, ctrl_id, base_metrics, cur_metrics, now_iso
            )
            drift_items.extend(items)
    else:
        # No prior baseline run: check absolute compliance violations as initial drift baseline
        for collector, cur_payload in current_evidence.items():
            ctrl_id = cur_payload.get("control_id", "UNKNOWN")
            metrics = cur_payload.get("metrics", {})
            if metrics.get("open_security_groups", 0) > 0:
                drift_items.append(
                    DriftItem(
                        collector=collector,
                        control_id=ctrl_id,
                        field_name="open_security_groups",
                        baseline_value=0,
                        current_value=metrics["open_security_groups"],
                        severity="CRITICAL",
                        description=f"Initial baseline flagged {metrics['open_security_groups']} open security groups",
                        timestamp=now_iso,
                    )
                )
            if metrics.get("unencrypted_data_stores", 0) > 0:
                drift_items.append(
                    DriftItem(
                        collector=collector,
                        control_id=ctrl_id,
                        field_name="unencrypted_data_stores",
                        baseline_value=0,
                        current_value=metrics["unencrypted_data_stores"],
                        severity="CRITICAL",
                        description=f"Initial baseline flagged {metrics['unencrypted_data_stores']} unencrypted data stores",
                        timestamp=now_iso,
                    )
                )
            if metrics.get("orphaned_accounts", 0) > 0:
                drift_items.append(
                    DriftItem(
                        collector=collector,
                        control_id=ctrl_id,
                        field_name="orphaned_accounts",
                        baseline_value=0,
                        current_value=metrics["orphaned_accounts"],
                        severity="HIGH",
                        description=f"Initial baseline flagged {metrics['orphaned_accounts']} orphaned accounts",
                        timestamp=now_iso,
                    )
                )

    report = DriftReport(
        timestamp=now_iso,
        provider=provider,
        baseline_date=base_dir.name if base_dir else None,
        current_date=cur_dir.name,
        drift_detected=len(drift_items) > 0,
        total_drift_items=len(drift_items),
        items=drift_items,
    )

    if record_audit and drift_items:
        try:
            append_audit_event(
                base=base.parent,
                command="drift",
                outcome="drift_detected",
                details={
                    "drift_count": len(drift_items),
                    "critical": sum(1 for i in drift_items if i.severity == "CRITICAL"),
                    "target": f"{cur_dir.name} vs {base_dir.name if base_dir else 'initial'}",
                },
            )
        except Exception as exc:
            logger.debug("Failed writing drift audit event: %s", exc)

    return report
