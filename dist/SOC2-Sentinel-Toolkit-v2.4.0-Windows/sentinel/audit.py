from __future__ import annotations

import getpass
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.paths import evidence_root
from sentinel.security import safe_file_mode


def _audit_path(base: Path | None) -> Path:
    return evidence_root(base) / ".sentinel-audit.jsonl"


def append_audit_event(
    *,
    base: Path | None,
    command: str,
    provider: str | None = None,
    control_id: str | None = None,
    collector: str | None = None,
    outcome: str,
    duration_ms: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": getpass.getuser(),
        "command": command,
        "provider": provider,
        "control_id": control_id,
        "collector": collector,
        "outcome": outcome,
        "duration_ms": duration_ms,
        "details": details or {},
    }
    path = _audit_path(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")
    safe_file_mode(path.parent, is_dir=True)
    safe_file_mode(path)


class AuditTimer:
    def __init__(self) -> None:
        self._started = time.monotonic()

    @property
    def duration_ms(self) -> int:
        return int((time.monotonic() - self._started) * 1000)