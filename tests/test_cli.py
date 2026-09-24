from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path


def test_cli_run_all_mock(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "run-all",
            "--provider",
            "mock",
            "--output-base",
            str(tmp_path),
            "--continue-on-error",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert len(summary["results"]) == 7
    assert summary["errors"] == {}


def test_cli_dry_run_mock(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "run",
            "encryption_status",
            "--provider",
            "mock",
            "--output-base",
            str(tmp_path),
            "--dry-run",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "dry_run" in result.stdout


# --- Consolidated from test_cli_direct.py ---
import json
import sys
from unittest.mock import patch

from sentinel import cli


def test_main_validate_command(capsys):
    with patch.object(sys, "argv", ["sentinel", "validate", "--provider", "mock"]):
        cli.main()
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["provider_status"] == "ok"


def test_main_run_mock(tmp_path, capsys):
    with patch.object(
        sys,
        "argv",
        [
            "sentinel",
            "run",
            "iam_access_review",
            "--provider",
            "mock",
            "--output-base",
            str(tmp_path),
        ],
    ):
        cli.main()
    assert capsys.readouterr().out.strip()


def test_main_run_all_mock(tmp_path, capsys):
    with patch.object(
        sys,
        "argv",
        ["sentinel", "run-all", "--provider", "mock", "--output-base", str(tmp_path), "--continue-on-error"],
    ):
        cli.main()
    data = json.loads(capsys.readouterr().out)
    assert "results" in data


def test_main_dry_run(capsys):
    with patch.object(sys, "argv", ["sentinel", "run", "iam_access_review", "--provider", "mock", "--dry-run"]):
        cli.main()
    data = json.loads(capsys.readouterr().out)
    assert data["dry_run"] is True


def test_main_verify(tmp_path, capsys):
    with patch.object(
        sys,
        "argv",
        ["sentinel", "run", "iam_access_review", "--provider", "mock", "--output-base", str(tmp_path)],
    ):
        cli.main()
    capsys.readouterr()
    day_dirs = [p for p in (tmp_path / "evidence").iterdir() if p.is_dir() and p.name != "manifests"]
    day_dir = day_dirs[0]
    with patch.object(sys, "argv", ["sentinel", "verify", str(day_dir)]):
        cli.main()
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data.get("verified")


def test_frozen_windows_no_args_launches_interactive_menu(tmp_path, capsys):
    with (
        patch.object(sys, "argv", ["sentinel.exe"]),
        patch.object(sys, "platform", "win32"),
        patch.object(sys, "frozen", True, create=True),
        patch.object(cli, "install_root", return_value=tmp_path),
        patch.object(cli, "_run_interactive_command", return_value=0) as run_command,
        patch("builtins.input", side_effect=["1", "", "q"]),
    ):
        cli.main()

    run_command.assert_called_once_with(
        [
            "run-all",
            "--provider",
            "mock",
            "--output-base",
            str(tmp_path),
            "--continue-on-error",
        ]
    )
    out = capsys.readouterr().out
    assert "SOC2 Sentinel Toolkit" in out
    assert "Run demo (mock provider)" in out
    assert "Operation completed." in out


def test_prompt_provider_retries_and_accepts_named_provider(capsys):
    with patch("builtins.input", side_effect=["invalid", "aws"]):
        assert cli._prompt_provider() == "aws"
    assert "Invalid provider choice." in capsys.readouterr().out


def test_prompt_provider_can_go_back():
    with patch("builtins.input", return_value="q"):
        assert cli._prompt_provider() is None


def test_run_interactive_command_restores_argv_on_system_exit():
    original = list(sys.argv)
    with patch.object(cli, "main", side_effect=SystemExit(3)):
        assert cli._run_interactive_command(["validate", "--provider", "mock"]) == 3
    assert sys.argv == original


def test_windows_launcher_validate_provider_path(tmp_path, capsys):
    parser = cli._parser()
    with (
        patch.object(cli, "install_root", return_value=tmp_path),
        patch.object(cli, "_prompt_provider", return_value="aws"),
        patch.object(cli, "_run_interactive_command", return_value=2) as run_command,
        patch("builtins.input", side_effect=["2", "", "q"]),
    ):
        cli._windows_launcher(parser)

    run_command.assert_called_once_with(["validate", "--provider", "aws"])
    out = capsys.readouterr().out
    assert "Operation finished with exit code 2." in out
    assert "Closing SOC2 Sentinel." in out


def test_windows_launcher_run_all_provider_path(tmp_path):
    parser = cli._parser()
    with (
        patch.object(cli, "install_root", return_value=tmp_path),
        patch.object(cli, "_prompt_provider", return_value="gcp"),
        patch.object(cli, "_run_interactive_command", return_value=0) as run_command,
        patch("builtins.input", side_effect=["3", "", "q"]),
    ):
        cli._windows_launcher(parser)

    run_command.assert_called_once_with(
        [
            "run-all",
            "--provider",
            "gcp",
            "--output-base",
            str(tmp_path),
            "--continue-on-error",
        ]
    )


def test_windows_launcher_help_invalid_and_back_paths(tmp_path, capsys):
    parser = cli._parser()
    with (
        patch.object(cli, "install_root", return_value=tmp_path),
        patch.object(cli, "_prompt_provider", return_value=None),
        patch.object(parser, "print_help") as print_help,
        patch("builtins.input", side_effect=["bad", "2", "3", "4", "", "q"]),
    ):
        cli._windows_launcher(parser)

    print_help.assert_called_once()
    out = capsys.readouterr().out
    assert "Invalid choice." in out


# --- Consolidated from test_cli_enterprise.py ---

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


# --- Consolidated from test_cli_extended.py ---
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dry_run_mock():
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "run", "iam_access_review", "--provider", "mock", "--dry-run"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["dry_run"] is True


def test_run_mock_collector(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "--allow-unknown-control",
            "run",
            "iam_access_review",
            "--provider",
            "mock",
            "--output-base",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode == 0


def test_unknown_control_rejected():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "run",
            "iam_access_review",
            "--provider",
            "mock",
            "--control-id",
            "UNKNOWN-1",
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode == 2


# --- Consolidated from test_cli_report.py ---
import json
import sys
from pathlib import Path
from unittest.mock import patch

from sentinel import cli

ROOT = Path(__file__).resolve().parents[1]


def test_main_report_cmmc(tmp_path, capsys):
    sample = ROOT / "data" / "cmmc-l2-controls-110.csv"
    if not sample.exists():
        return
    with patch.object(
        sys,
        "argv",
        ["sentinel", "report", "--input", str(sample), "--output-dir", str(tmp_path / "out"), "--mode", "cmmc"],
    ):
        cli.main()
    data = json.loads(capsys.readouterr().out)
    assert Path(data["json"]).exists()


# --- Consolidated from test_cli_validate.py ---
import json
import subprocess
import sys


def test_sentinel_validate_mock():
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "validate", "--provider", "mock"],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["config_valid"] is True
    assert data["provider_status"] == "ok"


# --- Consolidated from test_cli_verify.py ---
import json
import subprocess
import sys
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso


def _payload():
    return {
        "control_id": "CC6.1",
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {},
        "evidence_artifacts": [],
        "findings": [],
        "errors": [],
        "notes": "verify test",
        "provider": "mock",
    }


def test_verify_detects_tamper(tmp_path):
    report = write_evidence(_payload(), base=tmp_path, config=SentinelConfig())
    evidence_date = report.parent.parent
    report_path = report
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["notes"] = "tampered"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "verify",
            str(evidence_date),
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert "CC6.1" in data.get("failed", {})


# --- Consolidated from test_enterprise_cli.py ---
"""Unit tests for new Enterprise CLI subcommands."""

import json
from pathlib import Path

import pytest

from sentinel.cli import main


def test_cli_policy_list(capsys: pytest.CaptureFixture) -> None:
    import sys
    sys.argv = ["sentinel", "policy", "list"]
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_policy_evaluate(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "iam_access_review": {
            "metrics": {
                "mfa_enforced_percentage": 100.0,
                "orphaned_accounts": 0,
            }
        }
    }), encoding="utf-8")

    import sys
    sys.argv = ["sentinel", "policy", "evaluate", "--state-file", str(state_file)]
    try:
        main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "compliance_score" in data


def test_cli_github_audit_mock(capsys: pytest.CaptureFixture) -> None:
    import sys
    sys.argv = ["sentinel", "github", "audit", "--repo", "demo/app", "--mock"]
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["compliant"] is True
    assert data["repository"] == "demo/app"


def test_cli_tenant_and_token(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    # Tenant create
    sys.argv = ["sentinel", "tenant", "create", "cli-tenant-test", "--output-base", str(tmp_path)]
    main()
    captured = capsys.readouterr()
    t_data = json.loads(captured.out)
    assert t_data["status"] == "created"
    assert t_data["tenant_id"] == "cli-tenant-test"

    # Tenant list
    sys.argv = ["sentinel", "tenant", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert "cli-tenant-test" in list_data["tenants"]

    # Token create
    sys.argv = [
        "sentinel", "token", "create",
        "--user", "cli_admin",
        "--role", "SECURITY_ADMIN",
        "--tenant", "cli-tenant-test",
        "--expires", "3600",
    ]
    main()
    captured_tok = capsys.readouterr()
    tok_data = json.loads(captured_tok.out)
    assert tok_data["token"].startswith("sentinel_")
    assert tok_data["user"]["user_id"] == "cli_admin"


def test_cli_vault_seal_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    ev_date_dir = tmp_path / "evidence" / "2026-09-24" / "iam"
    ev_date_dir.mkdir(parents=True)
    (ev_date_dir / "report.json").write_text(json.dumps({"test": "data"}), encoding="utf-8")

    # Vault Seal
    sys.argv = ["sentinel", "vault", "seal", str(tmp_path / "evidence" / "2026-09-24"), "--output-base", str(tmp_path)]
    main()
    captured_seal = capsys.readouterr()
    seal_data = json.loads(captured_seal.out)
    assert "merkle_root" in seal_data

    # Vault Verify
    sys.argv = ["sentinel", "vault", "verify", "--output-base", str(tmp_path)]
    main()
    captured_ver = capsys.readouterr()
    ver_data = json.loads(captured_ver.out)
    assert ver_data["valid"] is True
    assert ver_data["total_blocks"] == 1


def test_cli_vendor_risk_workflow(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    # Add vendor
    sys.argv = [
        "sentinel", "vendor-risk", "add",
        "--id", "v-github",
        "--name", "GitHub Enterprise",
        "--tier", "TIER_1_CRITICAL",
        "--classification", "CONFIDENTIAL",
        "--soc2-expires", "2030-01-01T00:00:00Z",
        "--dpa", "--mfa", "--encryption",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_add = capsys.readouterr()
    add_data = json.loads(captured_add.out)
    assert add_data["name"] == "GitHub Enterprise"

    # List vendors
    sys.argv = ["sentinel", "vendor-risk", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert len(list_data) == 1

    # Report
    sys.argv = ["sentinel", "vendor-risk", "report", "--output-base", str(tmp_path)]
    main()
    captured_rep = capsys.readouterr()
    rep_data = json.loads(captured_rep.out)
    assert rep_data["control_id"] == "CC9.2"
    assert rep_data["total_vendors"] == 1


def test_cli_access_review_workflow(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    ev_file = tmp_path / "iam_evidence.json"
    ev_file.write_text(json.dumps({
        "provider": "aws",
        "users": [{"user_id": "alice", "roles": ["Admin"], "mfa_enabled": True}],
    }), encoding="utf-8")

    # Start campaign
    sys.argv = [
        "sentinel", "access-review", "start",
        "--id", "CAMP-CLI-1",
        "--title", "CLI Test Campaign",
        "--period", "2026-Q3",
        "--evidence-file", str(ev_file),
        "--output-base", str(tmp_path),
    ]
    main()
    captured_start = capsys.readouterr()
    start_data = json.loads(captured_start.out)
    assert start_data["campaign_id"] == "CAMP-CLI-1"

    # List campaigns
    sys.argv = ["sentinel", "access-review", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert len(list_data) == 1

    # Make review decision on pending user
    sys.argv = [
        "sentinel", "access-review", "decide",
        "--id", "CAMP-CLI-1",
        "--item-id", "CAMP-CLI-1-item-001",
        "--decision", "MAINTAIN",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_dec = capsys.readouterr()
    dec_data = json.loads(captured_dec.out)
    assert dec_data["campaign_id"] == "CAMP-CLI-1"

    # Signoff campaign
    sys.argv = [
        "sentinel", "access-review", "signoff",
        "--id", "CAMP-CLI-1",
        "--signer", "Chief Security Officer",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_sign = capsys.readouterr()
    sign_data = json.loads(captured_sign.out)
    assert sign_data["status"] == "COMPLETED"
    assert "sign_off_hash" in sign_data
