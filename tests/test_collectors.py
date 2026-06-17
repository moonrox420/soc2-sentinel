import json
from pathlib import Path

import pytest

from sentinel.collectors import COLLECTORS
from sentinel.collectors.self_assessment_report import generate_self_assessment_report
from sentinel.providers.mock import MockProvider
from sentinel.schema import validate_evidence


@pytest.fixture
def tmp_base(tmp_path):
    return tmp_path


def test_all_collectors_mock(tmp_base):
    provider = MockProvider()
    defaults = {
        "iam_access_review": "CC6.1",
        "log_aggregator": "CC7.1",
        "config_drift": "CC6.2",
        "encryption_status": "C1.2",
        "retention_check": "C1.4",
        "resilience_testing": "A1.2",
        "zt_continuous_verification": "ZT-1",
    }
    for name, fn in COLLECTORS.items():
        path = fn(provider, control_id=defaults[name], base=tmp_base)
        assert path.exists()
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_evidence(payload)
        assert payload["provider"] == "mock"


def test_log_aggregator_cui_export(tmp_base):
    provider = MockProvider()
    path = COLLECTORS["log_aggregator"](provider, base=tmp_base)
    cui_file = path.parent / "cui_events_export.json"
    assert cui_file.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload.get("cui_scoped") is True
    assert "T1078" in payload.get("attck_tags", [])


def test_self_assessment_cmmc_110(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sample = root / "data" / "cmmc-l2-controls-110.csv"
    if not sample.exists():
        pytest.skip("cmmc-l2-controls-110.csv not generated yet")
    json_path, md_path = generate_self_assessment_report(
        sample, output_dir=tmp_path / "out", mode="cmmc"
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["total_controls"] == 110
    assert report["met"] >= 20
    assert md_path.exists()


def test_self_assessment_zt(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sample = root / "data" / "zero-trust-pillars.csv"
    if not sample.exists():
        pytest.skip("zero-trust-pillars.csv missing")
    json_path, _ = generate_self_assessment_report(
        sample, output_dir=tmp_path / "out", mode="zt"
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["mode"] == "zt"
    assert report["total_controls"] == 7


def test_cmmc_generator_row_count():
    root = Path(__file__).resolve().parents[1]
    csv_path = root / "data" / "cmmc-l2-controls-110.csv"
    if not csv_path.exists():
        pytest.skip("cmmc csv missing")
    lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 111  # header + 110 rows