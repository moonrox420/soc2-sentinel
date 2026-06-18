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
from sentinel.status import resolve_status


def collect_log_aggregator(
    provider: Provider,
    *,
    control_id: str = "CC7.1",
    base: Path | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    try:
        snap = fetch_snapshot(provider.log_monitoring_snapshot, collector="log_aggregator")
    except ProviderError as exc:
        return write_failure_evidence(
            control_id=control_id,
            provider_name=provider.name,
            collector="log_aggregator",
            error=str(exc),
            base=base,
            config=cfg,
        )

    cui_events = snap.get("cui_relevant_events", [])
    metrics = {
        "active_trails": snap.get("active_trails", 0),
        "log_coverage_percent": snap.get("log_coverage_percent", 0),
        "max_gap_hours": snap.get("max_gap_hours", 0),
        "critical_control_failures_30d": snap.get("critical_control_failures_30d", 0),
        "config_recorder_all_supported": snap.get("config_recorder_all_supported", False),
        "cui_events_captured": len(cui_events),
        "cui_retention_days": snap.get("cui_retention_days", 0),
    }
    findings = [{**f, "severity": "high"} for f in snap.get("findings", [])]
    extra: dict[str, str] = {"log_completeness.json": json.dumps(snap, indent=2)}
    if cui_events:
        extra["cui_events_export.json"] = json.dumps(
            {"events": cui_events, "attck_summary": snap.get("attck_summary", {})},
            indent=2,
        )

    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": [],
        "findings": findings,
        "notes": "Log completeness, CUI-relevant events, and DFARS 7012 detection evidence.",
        "provider": provider.name,
        "cui_scoped": len(cui_events) > 0,
        "attck_tags": list(snap.get("attck_summary", {}).keys()),
    }
    apply_collection_metadata(payload, snap)
    log_collection_done(collector="log_aggregator", provider=provider.name, control_id=control_id, snap=snap)
    return write_evidence(payload, base=base, extra_files=extra, config=cfg)