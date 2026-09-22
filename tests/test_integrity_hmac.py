import json

import pytest

from sentinel.errors import ValidationError
from sentinel.integrity import build_manifest, verify_and_decrypt_artifact, verify_manifest
from sentinel.security import encrypt_bytes


def test_manifest_hmac_verification(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HMAC_KEY", "test-hmac-key")
    out = tmp_path / "CC6.1"
    out.mkdir()
    (out / "report.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(out, control_id="CC6.1", written_files=["report.json"])
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ok, issues = verify_manifest(out)
    assert ok
    (out / "report.json").write_text("{\"tampered\": true}", encoding="utf-8")
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
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert verify_and_decrypt_artifact(artifact) == b'{"ok": true}'

    manifest["hmac_sha256"] = "0" * 64
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValidationError, match="manifest verification failed"):
        verify_and_decrypt_artifact(artifact)
