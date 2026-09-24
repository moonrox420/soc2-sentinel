from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from sentinel.reporting import export_audit_pack, generate_executive_html_report
from sentinel.scoring import compute_compliance_scorecard


def test_generate_executive_html_report(tmp_path: Path):
    day_dir = tmp_path / "2026-09-23"
    ctrl_dir = day_dir / "CC6.1"
    ctrl_dir.mkdir(parents=True)
    (ctrl_dir / "evidence.json").write_text(json.dumps({"collector": "iam_access_review", "control_id": "CC6.1", "provider": "mock", "metrics": {}}))
    (day_dir / "manifest.json").write_text(json.dumps({"files": {"CC6.1/evidence.json": "sha256abc123"}}))

    scorecard = compute_compliance_scorecard(tmp_path, date_str="2026-09-23")
    html_out = generate_executive_html_report(scorecard, day_dir)

    assert "<!DOCTYPE html>" in html_out
    assert "SOC2 Sentinel Executive Compliance Report" in html_out
    assert "CC6.1" in html_out
    assert "sha256abc123" in html_out


def test_export_audit_pack(tmp_path: Path):
    day_dir = tmp_path / "2026-09-23"
    ctrl_dir = day_dir / "CC6.1"
    ctrl_dir.mkdir(parents=True)
    (ctrl_dir / "evidence.json").write_text(json.dumps({"collector": "iam_access_review", "control_id": "CC6.1", "provider": "mock", "metrics": {}}))
    (day_dir / "manifest.json").write_text(json.dumps({"files": {"CC6.1/evidence.json": "sha256abc123"}}))

    zip_path = export_audit_pack(day_dir, output_dir=tmp_path)
    assert zip_path.exists()
    assert zip_path.name.endswith(".zip")

    # Verify zip structure
    with zipfile.ZipFile(zip_path, "r") as archive:
        namelist = archive.namelist()
        assert any("AUDITOR_README.txt" in n for n in namelist)
        assert any("Executive-Report" in n for n in namelist)
        assert any("manifest.json" in n for n in namelist)


def test_export_audit_pack_missing_dir(tmp_path: Path):
    non_existent = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        export_audit_pack(non_existent)
