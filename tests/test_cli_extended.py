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