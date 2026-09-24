"""Unit tests for SOC 2 Security & Trust Center Engine."""

from pathlib import Path

from sentinel.trust_center import TrustCenterManager, TrustCenterProfile


def test_trust_center_profile_generation(tmp_path: Path):
    tcm = TrustCenterManager(base_dir=tmp_path)
    profile = tcm.get_profile()

    assert isinstance(profile, TrustCenterProfile)
    assert profile.overall_compliance_score > 0.0
    assert profile.continuous_monitoring_status == "ACTIVE_HEALTHY"
    assert len(profile.badges) >= 5
    assert len(profile.controls) >= 4
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
