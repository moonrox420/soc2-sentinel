import json

from sentinel.integrity import verify_manifest
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso


def test_manifest_verify_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_HMAC_KEY", raising=False)
    payload = {
        "control_id": "CC6.1",
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "metrics": {},
        "evidence_artifacts": [],
        "findings": [],
        "notes": "integrity test",
        "provider": "mock",
    }
    path = write_evidence(payload, base=tmp_path, extra_files={"note.txt": "x"})
    out_dir = path.parent
    assert verify_manifest(out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "artifacts" in manifest


# --- Consolidated from test_integrity_extended.py ---

from sentinel.integrity import build_manifest, verify_evidence_tree


def test_verify_manifest_roundtrip(tmp_path):
    out = tmp_path / "CC6.1"
    out.mkdir()
    (out / "report.json").write_text('{"ok": true}', encoding="utf-8")
    manifest = build_manifest(out, control_id="CC6.1", written_files=["report.json"])
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ok, issues = verify_manifest(out)
    assert ok
    assert not issues


def test_verify_tree(tmp_path):
    day = tmp_path / "2026-06-18"
    ctrl = day / "CC6.1"
    ctrl.mkdir(parents=True)
    (ctrl / "report.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(ctrl, control_id="CC6.1", written_files=["report.json"])
    (ctrl / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_evidence_tree(day)
    assert "CC6.1" in result["verified"]


# --- Consolidated from test_integrity_hmac.py ---

import pytest

from sentinel.errors import ValidationError
from sentinel.integrity import (
    verify_and_decrypt_artifact,
)
from sentinel.security import encrypt_bytes


def test_manifest_hmac_verification(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HMAC_KEY", "test-hmac-key")
    out = tmp_path / "CC6.1"
    out.mkdir()
    (out / "report.json").write_text("{}", encoding="utf-8")

    manifest = build_manifest(
        out,
        control_id="CC6.1",
        written_files=["report.json"],
    )
    (out / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    ok, issues = verify_manifest(out)
    assert ok
    assert not issues

    (out / "report.json").write_text(
        '{"tampered": true}',
        encoding="utf-8",
    )
    ok2, issues2 = verify_manifest(out)
    assert not ok2
    assert issues2


def test_verified_decrypt_checks_manifest_hmac_first(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "evidence-key")
    monkeypatch.setenv("SENTINEL_HMAC_KEY", "manifest-key")

    out = tmp_path / "CC6.1"
    out.mkdir()
    artifact = out / "report.json.enc"
    artifact.write_bytes(encrypt_bytes(b'{"ok": true}'))

    manifest = build_manifest(
        out,
        control_id="CC6.1",
        written_files=["report.json.enc"],
    )
    (out / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    assert verify_and_decrypt_artifact(artifact) == b'{"ok": true}'

    manifest["hmac_sha256"] = "0" * 64
    (out / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match="manifest verification failed",
    ):
        verify_and_decrypt_artifact(artifact)
