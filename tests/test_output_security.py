import json
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso, validate_evidence


def _payload(control_id: str = "CC6.1") -> dict:
    return {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "metrics": {"total_identities": 1},
        "evidence_artifacts": [],
        "findings": [],
        "notes": "test",
        "provider": "mock",
    }


def test_write_evidence_creates_manifest(tmp_path):
    path = write_evidence(
        _payload(),
        base=tmp_path,
        extra_files={"artifact.txt": "hello"},
        config=SentinelConfig(),
    )
    assert path.exists()
    manifest = path.parent / "manifest.json"
    assert manifest.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_evidence(payload)
    assert "artifact.txt" in payload["evidence_artifacts"]


def test_empty_extra_file_not_listed(tmp_path):
    path = write_evidence(
        _payload(),
        base=tmp_path,
        extra_files={"empty.csv": "   "},
        config=SentinelConfig(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "empty.csv" not in payload["evidence_artifacts"]