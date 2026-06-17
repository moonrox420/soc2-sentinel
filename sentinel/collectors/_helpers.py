from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentinel.config import SentinelConfig
from sentinel.errors import ProviderError
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso
from sentinel.security import redact_pii, sanitize_csv_cell


def fetch_snapshot(fn: Callable[[], dict[str, Any]], *, collector: str) -> dict[str, Any]:
    try:
        return fn()
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(f"{collector} snapshot failed: {exc}") from exc


def apply_partial_metadata(payload: dict[str, Any], snap: dict[str, Any]) -> None:
    if not snap.get("partial"):
        return
    if payload.get("status") == "green":
        payload["status"] = "yellow"
    errors = snap.get("errors") or []
    if errors:
        note = payload.get("notes", "")
        suffix = " Partial collection: " + "; ".join(errors)
        payload["notes"] = (note + suffix).strip()


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
        "metrics": {"collection_failed": True},
        "evidence_artifacts": [],
        "findings": [{"issue": error, "severity": "critical", "resource": collector}],
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