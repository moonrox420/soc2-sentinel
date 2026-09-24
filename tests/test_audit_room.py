"""Unit tests for SOC 2 Audit Room and Auditor Portal Engine."""

import json
from pathlib import Path

import pytest

from sentinel.audit_room import (
    TSC_CRITERIA_CATALOG,
    AuditRoomManager,
    AuditRoomStatus,
)


@pytest.fixture
def audit_room_env(tmp_path: Path) -> tuple[AuditRoomManager, Path]:
    ev_dir = tmp_path / "evidence" / "2026-09-01"
    ev_dir.mkdir(parents=True, exist_ok=True)
    iam_file = ev_dir / "identity_iam.json"
    iam_file.write_text(
        json.dumps({"provider": "mock", "users": ["alice"]}), encoding="utf-8"
    )
    enc_file = ev_dir / "encryption_status.json"
    enc_file.write_text(
        json.dumps({"provider": "mock", "encrypted": True}), encoding="utf-8"
    )

    arm = AuditRoomManager(base_dir=tmp_path)
    return arm, tmp_path


def test_create_and_get_audit_room(audit_room_env: tuple[AuditRoomManager, Path]):
    arm, tmp_path = audit_room_env
    room = arm.create_room(
        room_id="TEST-ROOM-2026",
        title="2026 SOC 2 Type II Examination",
        auditor_email="lead-auditor@pwc.com",
        period_start="2026-09-01",
        period_end="2026-09-30",
        expires_days=30,
        notes="External audit window for FY26",
    )

    assert room.room_id == "TEST-ROOM-2026"
    assert room.status == AuditRoomStatus.ACTIVE
    assert room.is_active() is True
    assert len(room.access_token) >= 32
    assert "2026-09-01" in room.evidence_dates

    # Retrieve room
    loaded = arm.get_room("TEST-ROOM-2026")
    assert loaded is not None
    assert loaded.title == "2026 SOC 2 Type II Examination"
    assert loaded.auditor_email == "lead-auditor@pwc.com"


def test_validate_auditor_access_and_logging(
    audit_room_env: tuple[AuditRoomManager, Path],
):
    arm, tmp_path = audit_room_env
    room = arm.create_room(
        room_id="ROOM-AUTH",
        title="Auth Test Room",
        auditor_email="auditor@firm.com",
        period_start="2026-09-01",
        period_end="2026-09-30",
    )

    # Invalid token
    ok, r_obj = arm.validate_access(
        "ROOM-AUTH", "wrong_token", "1.2.3.4", "TestBrowser"
    )
    assert ok is False
    assert r_obj is None

    # Valid token
    ok, r_obj = arm.validate_access(
        "ROOM-AUTH", room.access_token, "192.168.1.50", "Mozilla/5.0"
    )
    assert ok is True
    assert r_obj is not None
    assert len(r_obj.access_logs) == 1
    assert r_obj.access_logs[0]["ip_address"] == "192.168.1.50"


def test_control_crosswalk_and_csv(audit_room_env: tuple[AuditRoomManager, Path]):
    arm, tmp_path = audit_room_env
    room = arm.create_room(
        room_id="ROOM-MATRIX",
        title="Matrix Test Room",
        auditor_email="auditor@firm.com",
        period_start="2026-09-01",
        period_end="2026-09-30",
    )

    crosswalk = arm.build_control_crosswalk(room)
    assert len(crosswalk) == len(TSC_CRITERIA_CATALOG)

    # CC5.1 requires identity_iam which exists
    cc51 = next(c for c in crosswalk if c["control_id"] == "CC5.1")
    assert cc51["evidence_status"] == "SATISFIED"
    assert cc51["evidence_count"] >= 1

    # Export CSV
    csv_str = arm.export_control_crosswalk_csv(room)
    assert "Control ID,Category,Control Title" in csv_str
    assert "CC5.1" in csv_str
    assert "SATISFIED" in csv_str


def test_generate_html_summary_and_zip_export(
    audit_room_env: tuple[AuditRoomManager, Path],
):
    arm, tmp_path = audit_room_env
    room = arm.create_room(
        room_id="ROOM-EXPORT",
        title="Export Test Room",
        auditor_email="auditor@firm.com",
        period_start="2026-09-01",
        period_end="2026-09-30",
    )

    html = arm.generate_auditor_html_summary(room)
    assert "<!DOCTYPE html>" in html
    assert "ROOM-EXPORT" in html
    assert "Trust Services Criteria" in html

    zip_file = arm.export_audit_package_zip("ROOM-EXPORT")
    assert zip_file.exists()
    assert zip_file.stat().st_size > 500

    # Revoke room
    revoked = arm.revoke_room("ROOM-EXPORT")
    assert revoked is True
    updated = arm.get_room("ROOM-EXPORT")
    assert updated is not None
    assert updated.status == AuditRoomStatus.REVOKED
    assert updated.is_active() is False
