import json
from pathlib import Path

from sentinel.integrity import build_manifest, verify_manifest
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