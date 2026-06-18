import json

from sentinel.audit import AuditTimer, append_audit_event
from sentinel.paths import evidence_root


def test_audit_jsonl_shape(tmp_path):
    append_audit_event(
        base=tmp_path,
        command="run",
        provider="mock",
        control_id="CC6.1",
        collector="iam_access_review",
        outcome="success",
        duration_ms=42,
        details={"collection_quality": "complete", "error_count": 0},
    )
    path = evidence_root(tmp_path) / ".sentinel-audit.jsonl"
    assert path.exists()
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["command"] == "run"
    assert record["duration_ms"] == 42


def test_audit_timer():
    timer = AuditTimer()
    assert timer.duration_ms >= 0