from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import resolve_status


def collect_config_drift(
    provider: Provider,
    *,
    control_id: str = "CC6.2",
    base: Path | None = None,
) -> Path:
    snap = provider.config_and_auth_snapshot()
    metrics = {
        "mfa_enforcement_percent": snap.get("mfa_enforcement_percent", 0),
        "weak_auth_methods": snap.get("weak_auth_methods", 0),
        "open_http_listeners": snap.get("open_http_listeners", 0),
        "weak_tls_listeners": snap.get("weak_tls_listeners", 0),
        "unapproved_changes": snap.get("unapproved_changes", 0),
        "changes_missing_rollback_test": snap.get("changes_missing_rollback_test", 0),
        "issues": snap.get("issues", 0),
        "warnings": snap.get("warnings", 0),
    }
    findings = []
    if metrics["weak_auth_methods"]:
        findings.append({"issue": "users without MFA", "severity": "high"})
    if metrics["open_http_listeners"]:
        findings.append({"issue": "HTTP listeners on port 80", "severity": "medium"})
    if metrics["weak_tls_listeners"]:
        findings.append({"issue": "weak TLS policy on load balancer", "severity": "medium"})

    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": ["config_drift_report.json"],
        "findings": findings,
        "notes": "Authentication and configuration drift snapshot.",
        "provider": provider.name,
    }
    import json

    return write_evidence(
        payload,
        base=base,
        extra_files={"config_drift_report.json": json.dumps(snap, indent=2)},
    )