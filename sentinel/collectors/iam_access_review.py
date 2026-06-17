from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import resolve_status


def collect_iam_access_review(
    provider: Provider,
    *,
    control_id: str = "CC6.1",
    base: Path | None = None,
) -> Path:
    snap = provider.iam_access_snapshot()
    privileged_standing = snap.get("privileged_count", 0)
    jit_recommendations = snap.get("jit_recommendations") or [
        f"Convert {privileged_standing} standing privileged accounts to time-bound JIT access"
        if privileged_standing
        else "No JIT conversions required"
    ]
    metrics = {
        "total_identities": snap["total_identities"],
        "orphaned_accounts": snap["orphaned_accounts"],
        "privileged_count": snap["privileged_count"],
        "privileged_standing_count": privileged_standing,
        "days_since_last_review": snap.get("days_since_last_review"),
        "session_timeout_compliant": snap.get("session_timeout_compliant", True),
        "jit_recommendations_count": len(jit_recommendations),
    }
    findings = [
        {
            "resource": u.get("username", "unknown"),
            "issue": "orphaned account (>90d inactive)",
            "severity": "medium",
        }
        for u in snap.get("users", [])
        if u.get("orphaned")
    ]
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": ["iam_users_export.csv", "jit_recommendations.json"],
        "findings": findings,
        "notes": snap.get("notes", "IAM access review with JIT privileged access recommendations."),
        "provider": provider.name,
        "composite_checks": {"jit_recommendations": jit_recommendations},
    }
    import json

    return write_evidence(
        payload,
        base=base,
        extra_files={
            "iam_users_export.csv": snap.get("csv", ""),
            "jit_recommendations.json": json.dumps(jit_recommendations, indent=2),
        },
    )