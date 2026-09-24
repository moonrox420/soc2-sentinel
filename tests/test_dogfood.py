"""Unit tests for SOC 2 Continuous Self-Attestation & Dogfooding Assessor."""

import json
from pathlib import Path

from sentinel.dogfood import DogfoodAssessor, DogfoodReport


def test_dogfood_assessment_clean_run(tmp_path: Path):
    # Setup mock audit log and initialized directory
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps({"event": "TEST_AUDIT", "severity": "INFO", "timestamp": "2026-09-24T00:00:00Z"}) + "\n",
        encoding="utf-8",
    )

    assessor = DogfoodAssessor(base_dir=tmp_path)
    report = assessor.run_assessment()

    assert isinstance(report, DogfoodReport)
    assert report.total_checks >= 6
    assert report.compliance_score >= 80.0
    assert report.grade in ("A+", "A", "B")
    assert report.status == "COMPLIANT"

    # Check to_dict() serialization
    d = report.to_dict()
    assert "compliance_score" in d
    assert "checks" in d
    assert len(d["checks"]) == report.total_checks


def test_dogfood_check_details(tmp_path: Path):
    assessor = DogfoodAssessor(base_dir=tmp_path)
    report = assessor.run_assessment()

    crypto_chk = next(c for c in report.checks if c.criterion == "CC6.7")
    assert crypto_chk.status == "PASS"
    assert "AES-256-GCM" in crypto_chk.details.get("algorithms", [])

    secrets_chk = next(c for c in report.checks if c.criterion == "CC6.1")
    assert secrets_chk.status == "PASS"
