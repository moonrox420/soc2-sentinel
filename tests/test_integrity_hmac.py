import json

from sentinel.integrity import build_manifest, verify_manifest


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