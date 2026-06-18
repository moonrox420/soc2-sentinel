from __future__ import annotations

from typing import Any


def api_error(
    code: str,
    message: str,
    *,
    service: str = "",
    retryable: bool = False,
    severity: str = "medium",
) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "service": service,
        "retryable": retryable,
        "severity": severity,
    }


def collection_quality(errors: list[dict[str, Any]], *, checks_attempted: int, checks_succeeded: int) -> str:
    if checks_attempted == 0 or (errors and checks_succeeded == 0):
        return "failed"
    if errors:
        return "partial"
    return "complete"


def finalize_snapshot(
    data: dict[str, Any],
    errors: list[dict[str, Any]],
    *,
    checks_attempted: int,
    checks_succeeded: int,
) -> dict[str, Any]:
    merged = dict(data)
    merged["errors"] = list(errors)
    merged["collection_quality"] = collection_quality(
        errors, checks_attempted=checks_attempted, checks_succeeded=checks_succeeded
    )
    merged["partial"] = merged["collection_quality"] in {"partial", "failed"}
    return merged


def merge_results(*snapshots: dict[str, Any]) -> dict[str, Any]:
    """Merge multiple partial snapshot dicts (e.g. ZT composition)."""
    if not snapshots:
        return finalize_snapshot({}, [], checks_attempted=0, checks_succeeded=0)
    merged: dict[str, Any] = {}
    all_errors: list[dict[str, Any]] = []
    attempted = 0
    succeeded = 0
    for snap in snapshots:
        attempted += 1
        errors = snap.get("errors") or []
        if snap.get("collection_quality") != "failed":
            succeeded += 1
        all_errors.extend(errors)
        for key, value in snap.items():
            if key in {"errors", "collection_quality", "partial"}:
                continue
            if key not in merged:
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = merged[key] + value
            elif isinstance(value, int) and isinstance(merged.get(key), int):
                merged[key] = merged[key] + value
    return finalize_snapshot(merged, all_errors, checks_attempted=attempted, checks_succeeded=succeeded)