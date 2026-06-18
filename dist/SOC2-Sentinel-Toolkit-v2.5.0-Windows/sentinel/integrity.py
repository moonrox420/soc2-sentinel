from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from sentinel import __version__
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
    toolkit_version: str | None = None,
) -> dict[str, Any]:
    artifacts: dict[str, str] = {}
    for name in written_files:
        file_path = out_dir / name
        if file_path.exists():
            artifacts[name] = sha256_file(file_path)
    manifest: dict[str, Any] = {
        "control_id": control_id,
        "generated_at": utc_now_iso(),
        "toolkit_version": toolkit_version or __version__,
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


def verify_manifest(out_dir: Path) -> tuple[bool, list[str]]:
    issues: list[str] = []
    path = out_dir / "manifest.json"
    if not path.exists():
        return False, ["manifest.json missing"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, ["manifest.json invalid JSON"]
    artifacts = manifest.get("artifacts", {})
    for name, expected in artifacts.items():
        file_path = out_dir / name
        if not file_path.exists():
            issues.append(f"missing artifact: {name}")
            continue
        if sha256_file(file_path) != expected:
            issues.append(f"hash mismatch: {name}")
    hmac_key = os.environ.get("SENTINEL_HMAC_KEY", "").strip()
    stored = manifest.get("hmac_sha256")
    if hmac_key:
        if not stored:
            issues.append("HMAC key set but manifest has no hmac_sha256")
        else:
            canonical = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hmac_sign(canonical, secret=hmac_key) != stored:
                issues.append("HMAC verification failed")
    elif stored:
        issues.append("manifest has HMAC but SENTINEL_HMAC_KEY not set")
    return len(issues) == 0, issues


def verify_evidence_tree(evidence_dir: Path) -> dict[str, Any]:
    """Verify all control directories under an evidence date folder."""
    results: dict[str, Any] = {"verified": [], "failed": {}, "total": 0}
    if not evidence_dir.exists():
        return {"error": f"directory not found: {evidence_dir}", "verified": [], "failed": {}}
    for child in sorted(evidence_dir.iterdir()):
        if not child.is_dir() or child.name in {"manifests"}:
            continue
        ok, issues = verify_manifest(child)
        results["total"] += 1
        if ok:
            results["verified"].append(child.name)
        else:
            results["failed"][child.name] = issues
    return results