from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.collectors._helpers import (
    apply_partial_metadata,
    fetch_snapshot,
    write_failure_evidence,
)
from sentinel.config import SentinelConfig
from sentinel.errors import ProviderError
from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import resolve_status


def collect_retention_check(
    provider: Provider,
    *,
    control_id: str = "C1.4",
    base: Path | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    try:
        snap = fetch_snapshot(provider.retention_snapshot, collector="retention_check")
    except ProviderError as exc:
        return write_failure_evidence(
            control_id=control_id,
            provider_name=provider.name,
            collector="retention_check",
            error=str(exc),
            base=base,
            config=cfg,
        )

    metrics = {
        "objects_past_retention": snap.get("objects_past_retention", 0),
        "retention_policy_cutoff": snap.get("retention_policy_cutoff"),
    }
    findings = [{**f, "severity": "high"} for f in snap.get("findings", [])]
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": [],
        "findings": findings,
        "notes": "Retention and secure disposal evidence for C1.4.",
        "provider": provider.name,
    }
    apply_partial_metadata(payload, snap)
    return write_evidence(
        payload,
        base=base,
        extra_files={"retention_report.json": json.dumps(snap, indent=2)},
        config=cfg,
    )