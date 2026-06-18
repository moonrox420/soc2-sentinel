from __future__ import annotations

import json
import os
import shutil
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Any, Iterator

from sentinel.config import SentinelConfig
from sentinel.errors import ValidationError as SentinelValidationError
from sentinel.integrity import build_manifest, write_manifest
from sentinel.paths import evidence_root
from sentinel.schema import validate_evidence
from sentinel.security import encrypt_bytes, encryption_enabled, safe_file_mode
from sentinel.validation import resolve_safe_output_base, sanitize_artifact_name, sanitize_control_id

try:
    import portalocker
except ImportError:  # pragma: no cover
    portalocker = None  # type: ignore


@contextmanager
def _control_dir_lock(out_dir: Path) -> Iterator[None]:
    lock_path = out_dir / ".lock"
    if portalocker is None:
        yield
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    with portalocker.Lock(str(lock_path), "w", timeout=120) as _handle:
        yield


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


def _verify_artifacts_exist(out_dir: Path, artifacts: list[str]) -> None:
    missing = [name for name in artifacts if not (out_dir / name).exists()]
    if missing:
        raise SentinelValidationError(f"evidence artifacts missing on disk: {missing}")


def _backup_manifest(out_dir: Path, *, run_day: date, safe_base: Path, control_id: str) -> None:
    manifest = out_dir / "manifest.json"
    if not manifest.exists():
        return
    backup_dir = evidence_root(safe_base) / run_day.isoformat() / "manifests"
    backup_dir.mkdir(parents=True, exist_ok=True)
    safe_file_mode(backup_dir, is_dir=True)
    dest = backup_dir / f"{control_id}.json"
    shutil.copy2(manifest, dest)
    safe_file_mode(dest)


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
    control_id = sanitize_control_id(
        str(payload.get("control_id", "")),
        strict_allowlist=cfg.validation.strict_allowlist,
    )
    payload["control_id"] = control_id
    payload.setdefault("errors", [])
    payload.setdefault("collection_quality", "complete")

    encrypt_flag = cfg.evidence.encrypt
    do_encrypt, secret = encryption_enabled(config_flag=encrypt_flag)

    if extra_files:
        for name in extra_files:
            sanitize_artifact_name(name)

    run_day = day or date.today()
    out_dir = evidence_root(safe_base) / run_day.isoformat() / control_id

    with _control_dir_lock(out_dir):
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

        report_name = "report.json"
        artifacts_written.append(report_name)
        payload["evidence_artifacts"] = list(artifacts_written)
        report_path = out_dir / report_name
        report_content = json.dumps(payload, indent=2)
        report_written = _atomic_write_text(
            report_path, report_content, encrypt=do_encrypt, secret=secret
        )
        written_files.append(report_written)
        validate_evidence(payload)

        _verify_artifacts_exist(out_dir, artifacts_written)

        validate_evidence(payload)

        manifest = build_manifest(out_dir, control_id=control_id, written_files=written_files)
        write_manifest(out_dir, manifest)
        written_files.append("manifest.json")

        if cfg.evidence.manifest_backup:
            _backup_manifest(out_dir, run_day=run_day, safe_base=safe_base, control_id=control_id)

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