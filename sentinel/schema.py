from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from sentinel.paths import install_root

_SCHEMA_PATH = install_root() / "data" / "evidence-schema.json"


def load_schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_evidence(payload: dict[str, Any]) -> None:
    jsonschema.validate(instance=payload, schema=load_schema())


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")