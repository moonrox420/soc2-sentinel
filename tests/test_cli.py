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