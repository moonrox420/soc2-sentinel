import json
import subprocess
import sys
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso


def _payload():
    return {
        "control_id": "CC6.1",
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {},
        "evidence_artifacts": [],
        "findings": [],
        "errors": [],
        "notes": "verify test",
        "provider": "mock",
    }


def test_verify_detects_tamper(tmp_path):
    report = write_evidence(_payload(), base=tmp_path, config=SentinelConfig())
    evidence_date = report.parent.parent
    report_path = report
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["notes"] = "tampered"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "verify",
            str(evidence_date),
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert "CC6.1" in data.get("failed", {})