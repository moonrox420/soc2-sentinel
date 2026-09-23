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
