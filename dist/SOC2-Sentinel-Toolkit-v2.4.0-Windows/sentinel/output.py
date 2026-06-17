from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from typing import Any

from sentinel.config import SentinelConfig
from sentinel.errors import ValidationError as SentinelValidationError
from sentinel.integrity import build_manifest, write_manifest
from sentinel.paths import evidence_root
from sentinel.schema import validate_evidence
from sentinel.security import encrypt_bytes, encryption_enabled, safe_file_mode
from sentinel.validation import resolve_safe_output_base, sanitize_artifact_name, sanitize_control_id


def _atomic_write_text(path: Path, content: str, *, encrypt: bool, secret: str | None) -> str:
    data = content.encode("utf-8")
    written_name = path.name
    if encrypt and secret:
        data = encrypt_bytes(data, secret=secret)
        path = path.with_suffix(path.suffix + ".enc")
        written_name = path.name
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    safe_file_mode(tmp)
    os.replace(tmp, path)
    safe_file_mode(path)
    return written_name


def write_evidence(
    payload: dict[str, Any],
    *,
    base: Path | None = None,
    day: date | None = None,
    extra_files: dict[str, str] | None = None,
    config: SentinelConfig | None = None,
) -> Path:
    cfg = config or SentinelConfig()
    safe_base = resolve_safe_output_base(base)
    control_id = sanitize_control_id(str(payload.get("control_id", "")))
    payload["control_id"] = control_id

    encrypt_flag = cfg.evidence.encrypt
    do_encrypt, secret = encryption_enabled(config_flag=encrypt_flag)

    if extra_files:
        for name in extra_files:
            sanitize_artifact_name(name)

    validate_evidence(payload)
    run_day = day or date.today()
    out_dir = evidence_root(safe_base) / run_day.isoformat() / control_id
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_file_mode(out_dir, is_dir=True)

    written_files: list[str] = []
    artifacts_written: list[str] = []

    if extra_files:
        for name, content in extra_files.items():
            safe_name = sanitize_artifact_name(name)
            if not content or not content.strip():
                continue
            artifact_path = out_dir / safe_name
            actual_name = _atomic_write_text(
                artifact_path, content, encrypt=do_encrypt, secret=secret
            )
            written_files.append(actual_name)
            artifacts_written.append(actual_name)

    payload["evidence_artifacts"] = list(artifacts_written)

    report_path = out_dir / "report.json"
    report_content = json.dumps(payload, indent=2)
    report_written = _atomic_write_text(
        report_path, report_content, encrypt=do_encrypt, secret=secret
    )
    written_files.append(report_written)

    validate_evidence(payload)

    manifest = build_manifest(out_dir, control_id=control_id, written_files=written_files)
    manifest_path = write_manifest(out_dir, manifest)
    written_files.append("manifest.json")

    if do_encrypt:
        stub = {
            "encrypted": True,
            "control_id": control_id,
            "artifacts": written_files,
            "manifest": "manifest.json",
        }
        stub_path = out_dir / "report.meta.json"
        stub_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")
        safe_file_mode(stub_path)

    return out_dir / report_written