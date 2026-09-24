"""Unit tests for SOC 2 Security & Trust Center Engine."""

import json
from pathlib import Path

from sentinel.trust_center import TrustCenterManager, TrustCenterProfile
from sentinel.vendor_risk import (
    DataClassification,
    SecurityQuestionnaire,
    Vendor,
    VendorRiskManager,
    VendorTier,
)


def test_trust_center_profile_generation(tmp_path: Path):
    tcm = TrustCenterManager(base_dir=tmp_path)
    profile_empty = tcm.get_profile()

    assert isinstance(profile_empty, TrustCenterProfile)
    assert profile_empty.overall_compliance_score == 0.0
    assert profile_empty.continuous_monitoring_status == "INITIALIZING"

    # Seed evidence and subprocessor
    ev_dir = tmp_path / "evidence" / "2026-09-24" / "iam_access_review"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "report.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "collection_quality": "complete",
                "users": [{"mfa_enabled": True}],
                "mfa_coverage_pct": 100.0,
            }
        ),
        encoding="utf-8",
    )

    vrm = VendorRiskManager(base_root=tmp_path)
    vrm.save_vendor(
        Vendor(
            vendor_id="aws",
            name="Amazon Web Services",
            service_description="Cloud Hosting",
            tier=VendorTier.TIER_1_CRITICAL,
            data_classification=DataClassification.CONFIDENTIAL,
            questionnaire=SecurityQuestionnaire(has_soc2_type2=True, dpa_executed=True),
        )
    )

    profile = tcm.get_profile()
    assert profile.overall_compliance_score > 0.0
    assert len(profile.subprocessors) >= 1

    d = profile.to_dict()
    assert d["company_name"] == "SOC2 Sentinel Enterprise"
    assert "badges" in d
    assert "subprocessors" in d


def test_trust_center_html_export(tmp_path: Path):
    tcm = TrustCenterManager(base_dir=tmp_path)
    html = tcm.generate_trust_center_html()

    assert "<!DOCTYPE html>" in html
    assert "Security, Privacy & Trust Center" in html
    assert "Compliance Frameworks & Certifications" in html
    assert "Authorized Subprocessor Directory" in html
    assert "AES-256-GCM" in html
