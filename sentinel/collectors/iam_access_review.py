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
from sentinel.security import redact_pii
from sentinel.status import resolve_status


def collect_iam_access_review(
    provider: Provider,
    *,
    control_id: str = "CC6.1",
    base: Path | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    try:
        snap = fetch_snapshot(provider.iam_access_snapshot, collector="iam_access_review")
    except ProviderError as exc:
        return write_failure_evidence(
            control_id=control_id,
            provider_name=provider.name,
            collector="iam_access_review",
            error=str(exc),
            base=base,
            config=cfg,
        )

    privileged_standing = snap.get("privileged_count", 0)
    jit_recommendations = snap.get("jit_recommendations") or [
        f"Convert {privileged_standing} standing privileged accounts to time-bound JIT access"
        if privileged_standing
        else "No JIT conversions required"
    ]
    metrics = {
        "total_identities": snap.get("total_identities", 0),
        "orphaned_accounts": snap.get("orphaned_accounts", 0),
        "privileged_count": snap.get("privileged_count", 0),
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
        "evidence_artifacts": [],
        "findings": findings,
        "notes": snap.get("notes", "IAM access review with JIT privileged access recommendations."),
        "provider": provider.name,
        "composite_checks": {"jit_recommendations": jit_recommendations},
    }
    apply_collection_metadata(payload, snap)
    log_collection_done(collector="iam_access_review", provider=provider.name, control_id=control_id, snap=snap)

    csv_content = snap.get("csv", "")
    if cfg.evidence.redact_pii and csv_content:
        csv_content = redact_pii(csv_content)

    extra_files: dict[str, str] = {
        "jit_recommendations.json": json.dumps(jit_recommendations, indent=2),
    }
    if csv_content.strip():
        extra_files["iam_users_export.csv"] = csv_content

    return write_evidence(payload, base=base, extra_files=extra_files, config=cfg)