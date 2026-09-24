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


def collect_zt_continuous_verification(
    provider: Provider,
    *,
    control_id: str = "ZT-1",
    base: Path | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    try:
        snap = fetch_snapshot(provider.zt_verification_snapshot, collector="zt_continuous_verification")
    except ProviderError as exc:
        return write_failure_evidence(
            control_id=control_id,
            provider_name=provider.name,
            collector="zt_continuous_verification",
            error=str(exc),
            base=base,
            config=cfg,
        )

    iam_review_days = snap.get("iam_review_days_ago")
    mfa_enforcement = snap.get("mfa_enforcement_percent")
    orphaned_accounts = snap.get("orphaned_accounts")
    session_timeout = snap.get("session_timeout_compliant")

    checks = {
        "iam_review_current": iam_review_days is not None and iam_review_days <= 90,
        "encryption_green": snap.get("encryption_status") == "green",
        "mfa_enforced": mfa_enforcement is not None and mfa_enforcement >= 100,
        "orphaned_within_threshold": (
            orphaned_accounts is not None and orphaned_accounts <= 7
        ),
        "session_timeout_compliant": session_timeout is True,
    }
    failed = [name for name, ok in checks.items() if not ok]
    status = "green" if not failed else ("yellow" if len(failed) <= 2 else "red")

    metrics = {
        "checks_passed": sum(1 for v in checks.values() if v),
        "checks_total": len(checks),
        "orphaned_accounts": orphaned_accounts,
        "unencrypted_resources": snap.get("unencrypted_resources", 0),
        "privileged_standing_count": snap.get("privileged_standing_count", 0),
        "mfa_enforcement_percent": mfa_enforcement,
        "mfa_registered_percent": snap.get("mfa_registered_percent"),
        "issues": len(failed),
    }
    pillar_scores = snap.get("pillar_scores", {})
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": status,
        "metrics": metrics,
        "evidence_artifacts": [],
        "findings": [{"issue": f"failed: {name}", "severity": "medium"} for name in failed],
        "notes": "Zero Trust evidence gate. Unmeasured controls fail closed; pillar maturity is only emitted where provenance exists.",
        "provider": provider.name,
        "composite_checks": checks,
        "attck_tags": ["T1078", "T1550"],
    }
    apply_collection_metadata(payload, snap)
    log_collection_done(
        collector="zt_continuous_verification",
        provider=provider.name,
        control_id=control_id,
        snap=snap,
    )
    export = {**snap, "checks": checks, "pillar_scores": pillar_scores}
    return write_evidence(
        payload,
        base=base,
        extra_files={"zt_verification.json": json.dumps(export, indent=2)},
        config=cfg,
    )
