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