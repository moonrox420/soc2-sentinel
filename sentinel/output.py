from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from sentinel.schema import validate_evidence


def evidence_root(base: Path | None = None) -> Path:
    root = base or Path.cwd()
    return root / "evidence"


def write_evidence(
    payload: dict[str, Any],
    *,
    base: Path | None = None,
    day: date | None = None,
    extra_files: dict[str, str] | None = None,
) -> Path:
    validate_evidence(payload)
    run_day = day or date.today()
    control_id = payload["control_id"]
    out_dir = evidence_root(base) / run_day.isoformat() / control_id
    out_dir.mkdir(parents=True, exist_ok=True)

    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if extra_files:
        for name, content in extra_files.items():
            (out_dir / name).write_text(content, encoding="utf-8")
            if name not in payload["evidence_artifacts"]:
                payload["evidence_artifacts"].append(name)
        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return report_path