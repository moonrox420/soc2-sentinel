from sentinel.collectors._helpers import (
    failure_payload,
    sanitize_csv_export,
    worst_status,
    write_failure_evidence,
)
from sentinel.config import SentinelConfig


def test_failure_payload_shape():
    p = failure_payload(control_id="CC6.1", provider_name="mock", collector="x", error="boom")
    assert p["collection_quality"] == "failed"
    assert p["errors"][0]["code"] == "CollectionFailed"


def test_sanitize_csv_export():
    csv_text = sanitize_csv_export([{"name": "=evil", "val": 1}])
    assert "'=evil" in csv_text


def test_write_failure_evidence(tmp_path):
    path = write_failure_evidence(
        control_id="CC6.1",
        provider_name="mock",
        collector="test",
        error="fail",
        base=tmp_path,
        config=SentinelConfig(),
    )
    assert path.name == "report.json"


def test_worst_status_order():
    assert worst_status("green", "yellow", "red") == "red"