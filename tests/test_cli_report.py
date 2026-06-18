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