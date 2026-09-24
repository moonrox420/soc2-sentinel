"""Unit tests for Vendor Risk Management & SOC 2 CC9.2."""

from pathlib import Path

from sentinel.vendor_risk import (
    DataClassification,
    SecurityQuestionnaire,
    Vendor,
    VendorRiskManager,
    VendorStatus,
    VendorTier,
)


def test_questionnaire_score_calculation() -> None:
    q_full = SecurityQuestionnaire(
        has_soc2_type2=True,
        soc2_clean_opinion=True,
        enforces_mfa=True,
        encrypts_data_at_rest=True,
        encrypts_data_in_transit=True,
        has_annual_pentest=True,
        has_incident_response_plan=True,
        has_business_continuity_plan=True,
        dpa_executed=True,
        has_background_checks=True,
    )
    assert q_full.calculate_score() == 100.0

    q_empty = SecurityQuestionnaire()
    assert q_empty.calculate_score() == 0.0


def test_vendor_risk_evaluation_and_findings() -> None:
    # Compliant vendor
    q_good = SecurityQuestionnaire(
        has_soc2_type2=True,
        enforces_mfa=True,
        encrypts_data_at_rest=True,
        dpa_executed=True,
    )
    vendor_good = Vendor(
        vendor_id="v-aws",
        name="Amazon Web Services",
        service_description="Cloud Hosting",
        tier=VendorTier.TIER_1_CRITICAL,
        data_classification=DataClassification.CONFIDENTIAL,
        soc2_valid_until="2030-01-01T00:00:00Z",
        questionnaire=q_good,
    )
    vendor_good.evaluate_risk()
    assert vendor_good.risk_score >= 50.0

    # High risk vendor with expired report and missing DPA
    q_bad = SecurityQuestionnaire(has_soc2_type2=False, dpa_executed=False)
    vendor_bad = Vendor(
        vendor_id="v-insecure",
        name="Legacy SaaS Tool",
        service_description="Marketing Tracker",
        tier=VendorTier.TIER_1_CRITICAL,
        data_classification=DataClassification.RESTRICTED,
        soc2_valid_until="2020-01-01T00:00:00Z",
        questionnaire=q_bad,
    )
    vendor_bad.evaluate_risk()
    assert vendor_bad.status in (VendorStatus.CONDITIONAL, VendorStatus.REJECTED)
    assert any("expired" in f.lower() for f in vendor_bad.findings)
    assert any("DPA" in f for f in vendor_bad.findings)


def test_vendor_risk_manager_persistence_and_cc92_report(tmp_path: Path) -> None:
    mgr = VendorRiskManager(tmp_path)
    assert len(mgr.list_vendors()) == 0

    v1 = Vendor(
        vendor_id="v-datadog",
        name="Datadog",
        service_description="APM & Logging",
        tier=VendorTier.TIER_2_HIGH,
        data_classification=DataClassification.INTERNAL,
        soc2_valid_until="2030-01-01T00:00:00Z",
        questionnaire=SecurityQuestionnaire(
            has_soc2_type2=True, enforces_mfa=True, encrypts_data_at_rest=True
        ),
    )
    mgr.save_vendor(v1)

    vendors = mgr.list_vendors()
    assert len(vendors) == 1
    assert vendors[0].name == "Datadog"

    fetched = mgr.get_vendor("v-datadog")
    assert fetched is not None
    assert fetched.vendor_id == "v-datadog"

    report = mgr.generate_cc92_report()
    assert report["control_id"] == "CC9.2"
    assert report["total_vendors"] == 1
    assert "average_compliance_score" in report
