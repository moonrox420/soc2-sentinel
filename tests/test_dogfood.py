"""Unit tests for SOC 2 Continuous Self-Attestation & Dogfooding Assessor."""

import json
from pathlib import Path

from sentinel.dogfood import DogfoodAssessor, DogfoodReport


def test_dogfood_assessment_clean_run(tmp_path: Path):
    # Setup mock audit log and initialized directory
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "event": "TEST_AUDIT",
                "severity": "INFO",
                "timestamp": "2026-09-24T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Seed evidence run
    ev_dir = tmp_path / "evidence" / "2026-09-24" / "iam_access_review"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "report.json").write_text(
        json.dumps({"status": "PASS"}), encoding="utf-8"
    )

    assessor = DogfoodAssessor(base_dir=tmp_path)
    # Seal vault run
    assessor.vault.seal_run("2026-09-24")
    # Register compliant vendor
    from sentinel.vendor_risk import (
        DataClassification,
        SecurityQuestionnaire,
        Vendor,
        VendorTier,
    )

    q = SecurityQuestionnaire(
        has_soc2_type2=True,
        soc2_clean_opinion=True,
        enforces_mfa=True,
        encrypts_data_at_rest=True,
        encrypts_data_in_transit=True,
        dpa_executed=True,
    )
    v = Vendor(
        vendor_id="aws",
        name="Amazon Web Services",
        service_description="Cloud Infrastructure",
        tier=VendorTier.TIER_1_CRITICAL,
        data_classification=DataClassification.CONFIDENTIAL,
        questionnaire=q,
    )
    assessor.vrm.save_vendor(v)

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

    # Empty base dir yields honest warnings
    vault_chk = next(
        c
        for c in report.checks
        if c.criterion == "CC7.1" and c.check_id == "DOGFOOD-CC7.1-VAULT"
    )
    assert vault_chk.status == "WARN"
