"""Unit tests for RFC 5424 SIEM Telemetry and Multi-Sink Forwarder."""

import json
from pathlib import Path

from sentinel.telemetry import (
    AuditEvent,
    FileSink,
    HttpSink,
    MemorySink,
    SyslogFacility,
    SyslogSeverity,
    SyslogSink,
    TelemetryManager,
)


def test_audit_event_rfc5424_formatting() -> None:
    event = AuditEvent(
        action="UPDATE_SECURITY_POLICY",
        resource="policy/SOC2-CC6.1-MFA",
        outcome="SUCCESS",
        severity=SyslogSeverity.NOTICE,
        facility=SyslogFacility.AUTHPRIV,
        tenant_id="tenant-prod",
        user_id="alice",
        role="SECURITY_ADMIN",
        details={"status": "enabled"},
    )
    rfc = event.to_rfc5424(app_name="soc2-sentinel", hostname="test-node")
    assert rfc.startswith("<85>1 ")  # (10 * 8) + 5 = 85
    assert "test-node soc2-sentinel" in rfc
    assert 'tenant_id="tenant-prod"' in rfc
    assert 'user_id="alice"' in rfc
    assert 'role="SECURITY_ADMIN"' in rfc
    assert 'action="UPDATE_SECURITY_POLICY"' in rfc
    assert 'outcome="SUCCESS"' in rfc
    assert '"status": "enabled"' in rfc


def test_memory_sink_ring_buffer() -> None:
    sink = MemorySink(max_size=5)
    for i in range(10):
        sink.send(
            AuditEvent(
                action=f"ACTION_{i}",
                resource=f"res_{i}",
                tenant_id="t1" if i % 2 == 0 else "t2",
            )
        )

    events = sink.get_events(limit=10)
    assert len(events) == 5
    assert events[0]["action"] == "ACTION_9"

    t1_events = sink.get_events(tenant_id="t1")
    assert all(e["tenant_id"] == "t1" for e in t1_events)

    sink.clear()
    assert len(sink.get_events()) == 0


def test_file_sink_writing(tmp_path: Path) -> None:
    rfc_file = tmp_path / "syslog.log"
    json_file = tmp_path / "audit.jsonl"

    sink_rfc = FileSink(str(rfc_file), as_json=False)
    sink_json = FileSink(str(json_file), as_json=True)

    ev = AuditEvent(action="TEST_ACTION", resource="test_res")
    assert sink_rfc.send(ev) is True
    assert sink_json.send(ev) is True

    assert rfc_file.exists()
    assert "[sentinel@54321" in rfc_file.read_text(encoding="utf-8")

    assert json_file.exists()
    line = json.loads(json_file.read_text(encoding="utf-8").strip())
    assert line["action"] == "TEST_ACTION"


def test_telemetry_manager_dispatch() -> None:
    tm = TelemetryManager()
    mem = MemorySink(max_size=10)
    tm.add_sink(mem)

    event = tm.emit(
        action="TENANT_LOGIN",
        resource="auth_service",
        outcome="SUCCESS",
        tenant_id="tenant-alpha",
        user_id="user-1",
    )
    assert event.action == "TENANT_LOGIN"
    recent = tm.get_recent_events(limit=5, tenant_id="tenant-alpha")
    assert len(recent) > 0
    assert recent[0]["action"] == "TENANT_LOGIN"


def test_syslog_and_http_sink_resilience() -> None:
    # Testing network resilience / error tolerance when sinks point to closed test ports
    syslog_sink = SyslogSink(host="127.0.0.1", port=65500, protocol="UDP")
    ev = AuditEvent(action="UDP_TEST", resource="test")
    assert (
        syslog_sink.send(ev) is True
    )  # UDP socket send is non-blocking/fire-and-forget

    http_sink = HttpSink(endpoint_url="http://127.0.0.1:65501/logs", timeout=0.5)
    # Should catch exception and safely return False without crashing
    assert http_sink.send(ev) is False
