import json

from sentinel.integrity import build_manifest, verify_evidence_tree, verify_manifest


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