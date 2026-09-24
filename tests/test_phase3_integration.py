"""Integration tests for Phase 3 REST endpoints and CLI subcommands."""

import json
from pathlib import Path

import pytest

from sentinel.auth import Role, TokenManager, UserIdentity
from sentinel.cli import main
from sentinel.dashboard.server import DashboardHandler, DashboardServer


@pytest.fixture
def auth_token() -> str:
    user = UserIdentity(user_id="secadmin", role=Role.SUPER_ADMIN, tenant_id="default")
    return TokenManager.create_token(user)


def test_phase3_server_endpoints(tmp_path: Path, auth_token: str):
    server = DashboardServer(("127.0.0.1", 0), DashboardHandler, output_base=tmp_path)
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]

    import urllib.request
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    # 1. GET /api/trust-center
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/trust-center", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "overall_compliance_score" in data

    # 2. GET /trust-center (HTML)
    req = urllib.request.Request(f"http://127.0.0.1:{port}/trust-center")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        html = resp.read().decode()
        assert "<!DOCTYPE html>" in html

    # 3. GET /api/dogfood
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/dogfood", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "compliance_score" in data

    # 4. POST /api/audit-rooms (create)
    create_body = json.dumps({
        "room_id": "REST-ROOM-001",
        "title": "REST API Room",
        "auditor_email": "auditor@rest.com",
        "period_start": "2026-09-01",
        "period_end": "2026-09-30",
    }).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms", data=create_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        room_data = json.loads(resp.read().decode())
        assert room_data["room_id"] == "REST-ROOM-001"

    # 5. GET /api/audit-rooms/REST-ROOM-001
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms/REST-ROOM-001", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        details = json.loads(resp.read().decode())
        assert details["room"]["room_id"] == "REST-ROOM-001"
        assert "crosswalk" in details

    # 6. POST /api/audit-rooms/export
    export_body = json.dumps({"room_id": "REST-ROOM-001"}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms/export", data=export_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        exp_res = json.loads(resp.read().decode())
        assert exp_res["status"] == "success"

    # 7. POST /api/siem/export
    siem_body = json.dumps({"target": "NDJSON_FILE", "limit": 50}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/siem/export", data=siem_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        siem_res = json.loads(resp.read().decode())
        assert siem_res["status"] == "exported"

    server.shutdown()
    server.server_close()


def test_phase3_cli_commands(tmp_path: Path, monkeypatch, capsys):
    # Test CLI dogfood command
    monkeypatch.setattr("sys.argv", ["sentinel", "dogfood", "--output-base", str(tmp_path), "--json"])
    main()
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert "compliance_score" in res

    # Test CLI audit-room create & list
    monkeypatch.setattr("sys.argv", [
        "sentinel", "audit-room", "create",
        "--id", "CLI-ROOM-001",
        "--title", "CLI Audit Room",
        "--auditor", "auditor@cli.com",
        "--start", "2026-09-01",
        "--end", "2026-09-30",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["room_id"] == "CLI-ROOM-001"

    monkeypatch.setattr("sys.argv", [
        "sentinel", "audit-room", "list",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    rooms_list = json.loads(captured.out)
    assert len(rooms_list) >= 1

    # Test CLI trust-center view
    monkeypatch.setattr("sys.argv", [
        "sentinel", "trust-center", "view",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    tc_data = json.loads(captured.out)
    assert "overall_compliance_score" in tc_data

    # Test CLI siem export
    out_ndjson = tmp_path / "cli_siem.ndjson"
    monkeypatch.setattr("sys.argv", [
        "sentinel", "siem", "export",
        "--output-ndjson", str(out_ndjson),
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    siem_out = json.loads(captured.out)
    assert siem_out["status"] == "exported"
