from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.output import write_evidence
from sentinel.providers.base import Provider
from sentinel.schema import utc_now_iso
from sentinel.status import resolve_status


def collect_encryption_status(
    provider: Provider,
    *,
    control_id: str = "C1.2",
    base: Path | None = None,
) -> Path:
    snap = provider.encryption_snapshot()
    metrics = {
        "total_confidential_resources": snap.get("total_confidential_resources", 0),
        "encrypted_at_rest": snap.get("encrypted_at_rest", 0),
        "unencrypted_cui_count": snap.get("unencrypted_cui_count", 0),
        "fips_compliant_keys": snap.get("fips_compliant_keys", 0),
        "keys_pending_rotation": snap.get("keys_pending_rotation", 0),
        "tls_endpoints_checked": snap.get("tls_endpoints_checked", 0),
        "weak_cipher_endpoints": snap.get("weak_cipher_endpoints", 0),
    }
    findings = [
        {**f, "severity": "critical"} for f in snap.get("findings", [])
    ]
    payload: dict[str, Any] = {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": resolve_status(control_id, metrics),
        "metrics": metrics,
        "evidence_artifacts": ["encryption_status_report.json"],
        "findings": findings,
        "notes": "Encryption at rest and key management evidence for C1.1/C1.2.",
        "provider": provider.name,
    }
    import json

    return write_evidence(
        payload,
        base=base,
        extra_files={"encryption_status_report.json": json.dumps(snap, indent=2)},
    )