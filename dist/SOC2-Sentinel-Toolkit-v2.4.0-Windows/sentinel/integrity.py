from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.schema import utc_now_iso
from sentinel.security import hmac_sign, safe_file_mode


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    out_dir: Path,
    *,
    control_id: str,
    written_files: list[str],
    toolkit_version: str = "2.4.0",
) -> dict[str, Any]:
    artifacts: dict[str, str] = {}
    for name in written_files:
        file_path = out_dir / name
        if file_path.exists():
            artifacts[name] = sha256_file(file_path)
    manifest: dict[str, Any] = {
        "control_id": control_id,
        "generated_at": utc_now_iso(),
        "toolkit_version": toolkit_version,
        "artifacts": artifacts,
    }
    hmac_key = os.environ.get("SENTINEL_HMAC_KEY", "").strip()
    if hmac_key:
        canonical = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest["hmac_sha256"] = hmac_sign(canonical, secret=hmac_key)
    return manifest


def write_manifest(out_dir: Path, manifest: dict[str, Any]) -> Path:
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    safe_file_mode(path)
    return path


def verify_manifest(out_dir: Path) -> bool:
    path = out_dir / "manifest.json"
    if not path.exists():
        return False
    manifest = json.loads(path.read_text(encoding="utf-8"))
    artifacts = manifest.get("artifacts", {})
    for name, expected in artifacts.items():
        file_path = out_dir / name
        if not file_path.exists():
            return False
        if sha256_file(file_path) != expected:
            return False
    hmac_key = os.environ.get("SENTINEL_HMAC_KEY", "").strip()
    stored = manifest.get("hmac_sha256")
    if hmac_key and stored:
        canonical = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if hmac_sign(canonical, secret=hmac_key) != stored:
            return False
    return True