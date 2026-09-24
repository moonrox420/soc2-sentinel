from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sentinel.cli import _parser, main


def test_cli_parser_new_commands():
    parser = _parser()
    args_serve = parser.parse_args(["serve", "--port", "9090", "--no-browser"])
    assert args_serve.command == "serve"
    assert args_serve.port == 9090
    assert args_serve.no_browser is True

    args_dash = parser.parse_args(["dashboard", "--daemon"])
    assert args_dash.command == "dashboard"
    assert args_dash.daemon is True

    args_score = parser.parse_args(["scorecard", "--provider", "mock"])
    assert args_score.command == "scorecard"
    assert args_score.provider == "mock"

    args_drift = parser.parse_args(["drift", "--baseline", "2026-09-20"])
    assert args_drift.command == "drift"
    assert args_drift.baseline == "2026-09-20"

    args_pack = parser.parse_args(["audit-pack", "evidence/2026-09-23"])
    assert args_pack.command == "audit-pack"
    assert args_pack.evidence_dir == Path("evidence/2026-09-23")


def test_cli_scorecard_execution(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["sentinel", "scorecard", "--output-base", str(tmp_path)])
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "overall_posture_score" in data


def test_cli_drift_execution(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["sentinel", "drift", "--output-base", str(tmp_path)])
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "drift_detected" in data


def test_cli_audit_pack_execution(tmp_path: Path, capsys, monkeypatch):
    ev_dir = tmp_path / "2026-09-23"
    ev_dir.mkdir(parents=True)
    monkeypatch.setattr("sys.argv", ["sentinel", "audit-pack", str(ev_dir), "--output-dir", str(tmp_path)])
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "ok"
    assert "audit_pack_zip" in data


def test_cli_serve_dispatch(monkeypatch):
    with patch("sentinel.dashboard.server.run_dashboard_server") as mock_server:
        monkeypatch.setattr("sys.argv", ["sentinel", "serve", "--port", "8888", "--no-browser"])
        main()
        mock_server.assert_called_once()
