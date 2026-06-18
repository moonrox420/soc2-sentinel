from __future__ import annotations

import json
from typing import Any

import jsonschema

from sentinel.errors import ValidationError
from sentinel.paths import install_root

_SCHEMA_PATH = install_root() / "data" / "evidence-schema.json"


def load_schema() -> dict[str, Any]:
    if not _SCHEMA_PATH.exists():
        raise ValidationError(f"evidence schema not found: {_SCHEMA_PATH}")
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _enforce_collection_quality_rules(payload: dict[str, Any]) -> None:
    quality = payload.get("collection_quality")
    errors = payload.get("errors") or []
    artifacts = payload.get("evidence_artifacts") or []
    findings = payload.get("findings") or []

    critical_errors = [e for e in errors if e.get("severity") == "critical"]
    if quality == "complete":
        if critical_errors:
            raise ValidationError("collection_quality complete but critical errors present")
        if not artifacts:
            raise ValidationError("collection_quality complete requires evidence_artifacts")
    if quality == "failed" and artifacts and critical_errors:
        pass  # allowed — partial artifact write on hard failure

    if findings:
        for finding in findings:
            if "severity" not in finding:
                raise ValidationError("findings require severity when non-empty")


def validate_evidence(payload: dict[str, Any]) -> None:
    schema = load_schema()
    try:
        jsonschema.validate(instance=payload, schema=schema)
    except jsonschema.ValidationError as exc:
        path = " / ".join(str(p) for p in exc.absolute_path) or "(root)"
        raise ValidationError(
            f"evidence schema validation failed at {path}: {exc.message}",
            details={"path": path, "validator": exc.validator},
        ) from exc
    _enforce_collection_quality_rules(payload)


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")