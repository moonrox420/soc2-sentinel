from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentinel.config import SentinelConfig
from sentinel.errors import ProviderError
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso
from sentinel.security import redact_pii, sanitize_csv_cell

logger = logging.getLogger("sentinel.collectors")


def fetch_snapshot(fn: Callable[[], dict[str, Any]], *, collector: str) -> dict[str, Any]:
    try:
        return fn()
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(f"{collector} snapshot failed: {exc}") from exc


def apply_collection_metadata(payload: dict[str, Any], snap: dict[str, Any]) -> None:
    """Map provider snapshot errors and collection_quality into evidence payload."""
    errors = snap.get("errors") or []
    if errors and isinstance(errors[0], str):
        errors = [{"code": "ProviderError", "message": e, "severity": "high"} for e in errors]
    payload["errors"] = list(errors)
    quality = snap.get("collection_quality", "complete")
    payload["collection_quality"] = quality

    if quality == "failed":
        payload["status"] = "red"
    elif quality == "partial" and payload.get("status") == "green":
        payload["status"] = "yellow"


def worst_status(*statuses: str) -> str:
    if "red" in statuses:
        return "red"
    if "yellow" in statuses:
        return "yellow"
    return "green"


def failure_payload(
    *,
    control_id: str,
    provider_name: str,
    collector: str,
    error: str,
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": "red",
        "collection_quality": "failed",
        "metrics": {"collection_failed": True},
        "evidence_artifacts": [],
        "findings": [{"issue": error, "severity": "critical", "resource": collector}],
        "errors": [{"code": "CollectionFailed", "message": error, "severity": "critical"}],
        "notes": f"{collector} failed: {error}",
        "provider": provider_name,
    }


def write_failure_evidence(
    *,
    control_id: str,
    provider_name: str,
    collector: str,
    error: str,
    base: Path | None,
    config: SentinelConfig | None,
) -> Path:
    payload = failure_payload(
        control_id=control_id,
        provider_name=provider_name,
        collector=collector,
        error=error,
    )
    return write_evidence(payload, base=base, config=config)


def sanitize_csv_export(rows: list[dict[str, Any]], *, redact: bool = False) -> str:
    if not rows:
        return ""
    headers = list(rows[0].keys())
    lines = [",".join(headers)]
    for row in rows:
        cells = []
        for key in headers:
            value = row.get(key, "")
            text = sanitize_csv_cell(value)
            if redact and isinstance(value, str):
                text = sanitize_csv_cell(redact_pii(text))
            cells.append(text)
        lines.append(",".join(cells))
    return "\n".join(lines) + "\n"


def log_collection_done(
    *,
    collector: str,
    provider: str,
    control_id: str,
    snap: dict[str, Any],
) -> None:
    errors = snap.get("errors") or []
    logger.info(
        "collection complete",
        extra={
            "collector": collector,
            "provider": provider,
            "control_id": control_id,
            "collection_quality": snap.get("collection_quality", "complete"),
            "error_count": len(errors),
        },
    )