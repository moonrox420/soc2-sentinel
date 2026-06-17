from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso


def collect_zt_continuous_verification(
    provider: Provider,
    *,
    control_id: str = "ZT-1",
    base: Path | None = None,
) -> Path:
    snap = provider.zt_verification_snapshot()
    checks = {
        "iam_review_current": snap.get("iam_review_days_ago", 999) <= 90,
        "encryption_green": snap.get("encryption_status") == "green",
        "mfa_enforced": snap.get("mfa_enforcement_percent", 0) >= 100,
        "orphaned_within_threshold": snap.get("orphaned_accounts", 99) <= 7,
        "session_timeout_compliant": snap.get("session_timeout_compliant", False),
    }
    failed = [name for name, ok in checks.items() if not ok]
    status = "green" if not failed else ("yellow" if len(failed) <= 2 else "red")

    metrics = {
        "checks_passed": sum(1 for v in checks.values() if v),
        "checks_total": len(checks),
        "orphaned_accounts": snap.get("orphaned_accounts", 0),
        "unencrypted_resources": snap.get("unencrypted_resources", 0),
        "privileged_standing_count": snap.get("privileged_standing_count", 0),
        "mfa_enforcement_percent": snap.get("mfa_enforcement_percent", 0),
        "issues": len(failed),
    }
    pillar_scores = snap.get("pillar_scores", {})
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": status,
        "metrics": metrics,
        "evidence_artifacts": ["zt_verification.json"],
        "findings": [{"issue": f"failed: {name}", "severity": "medium"} for name in failed],
        "notes": "Zero Trust continuous verification composite gate (Identity + Data pillars).",
        "provider": provider.name,
        "composite_checks": checks,
        "attck_tags": ["T1078", "T1550"],
    }
    export = {**snap, "checks": checks, "pillar_scores": pillar_scores}
    return write_evidence(
        payload,
        base=base,
        extra_files={"zt_verification.json": json.dumps(export, indent=2)},
    )