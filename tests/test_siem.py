"""Unit tests for SIEM Exporter and Log Forwarding Engine."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel.siem import SIEMEvent, SIEMExporter


def test_siem_event_formatting():
    ev = SIEMEvent(
        event_id="evt-12345",
        event_type="ACCESS_REVIEW",
        severity="HIGH",
        data={"user": "bob", "action": "REVOKED"},
    )

    rfc_str = ev.to_rfc5424()
    assert "<" in rfc_str
    assert "soc2-sentinel" in rfc_str
    assert "evt-12345" in rfc_str

    ecs_dict = ev.to_ecs()
    assert ecs_dict["event"]["id"] == "evt-12345"
    assert ecs_dict["event"]["severity"] == "HIGH"
    assert ecs_dict["sentinel"]["user"] == "bob"


def test_siem_export_ndjson(tmp_path: Path):
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps({"event": "LOGIN_SUCCESS", "severity": "INFO", "user": "admin"}) + "\n"
        + json.dumps({"event": "DRIFT_DETECTED", "severity": "HIGH", "control": "CC6.6"}) + "\n",
        encoding="utf-8",
    )

    exporter = SIEMExporter(base_dir=tmp_path)
    out_file = tmp_path / "export.ndjson"
    cnt = exporter.export_to_ndjson_file(out_file)

    assert cnt == 2
    assert out_file.exists()
    lines = out_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    parsed = json.loads(lines[1])
    assert parsed["event"]["severity"] == "HIGH"


def test_siem_forward_splunk_mock(tmp_path: Path):
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps({"event": "VAULT_SEALED", "severity": "INFO", "block": "blk-1"}) + "\n",
        encoding="utf-8",
    )
    exporter = SIEMExporter(base_dir=tmp_path)

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ok, cnt, msg = exporter.forward_to_splunk_hec(
            endpoint_url="https://splunk.enterprise.internal:8088/services/collector/event",
            hec_token="fake-splunk-token",
        )
        assert ok is True
        assert cnt == 1
        assert "Successfully" in msg


def test_siem_forward_datadog_mock(tmp_path: Path):
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps({"event": "POLICY_PASS", "severity": "LOW"}) + "\n",
        encoding="utf-8",
    )
    exporter = SIEMExporter(base_dir=tmp_path)

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 202
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ok, cnt, msg = exporter.forward_to_datadog(api_key="fake-dd-api-key")
        assert ok is True
        assert cnt == 1


def test_siem_forward_webhook_mock(tmp_path: Path):
    audit_file = tmp_path / "sentinel_audit.jsonl"
    audit_file.write_text(
        json.dumps({"event": "CRITICAL_ALERT", "severity": "CRITICAL"}) + "\n",
        encoding="utf-8",
    )
    exporter = SIEMExporter(base_dir=tmp_path)

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ok, cnt, msg = exporter.forward_to_webhook(
            webhook_url="https://siem-collector.internal/webhook",
            secret_key="my-secret-key",
        )
        assert ok is True
        assert cnt == 1
