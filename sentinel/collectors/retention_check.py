from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import resolve_status


def collect_retention_check(
    provider: Provider,
    *,
    control_id: str = "C1.4",
    base: Path | None = None,
) -> Path:
    snap = provider.retention_snapshot()
    metrics = {
        "objects_past_retention": snap.get("objects_past_retention", 0),
        "retention_policy_cutoff": snap.get("retention_policy_cutoff"),
    }
    findings = [
        {**f, "severity": "high"} for f in snap.get("findings", [])
    ]
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": ["retention_report.json"],
        "findings": findings,
        "notes": "Retention and secure disposal evidence for C1.4.",
        "provider": provider.name,
    }
    import json

    return write_evidence(
        payload,
        base=base,
        extra_files={"retention_report.json": json.dumps(snap, indent=2)},
    )