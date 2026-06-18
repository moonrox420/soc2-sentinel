from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from sentinel.errors import ValidationError
from sentinel.schema import utc_now_iso
from sentinel.security import sanitize_csv_cell


def _load_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except csv.Error as exc:
        raise ValidationError(f"CSV parse error in {path}: {exc}") from exc
    if not rows:
        raise ValidationError(f"CSV input is empty: {path}")
    sanitized: list[dict[str, str]] = []
    for row in rows:
        sanitized.append({key: sanitize_csv_cell(value) for key, value in row.items()})
    return sanitized


def _status_field(row: dict[str, str], mode: str) -> str:
    if mode == "zt":
        return (row.get("Current Maturity") or row.get("current_maturity") or "Initial").strip()
    return (row.get("CMMC L2 Status") or row.get("cmmc_l2_status") or "Not Met").strip()


def generate_self_assessment_report(
    input_path: Path,
    *,
    output_dir: Path | None = None,
    mode: str = "cmmc",
) -> tuple[Path, Path]:
    if not input_path.exists():
        raise ValidationError(f"Input file not found: {input_path}")

    rows = _load_rows(input_path)
    family_scores: dict[str, dict[str, int]] = defaultdict(lambda: {"met": 0, "total": 0})
    overall = {"met": 0, "total": 0, "na": 0, "poam": 0}

    for row in rows:
        status = _status_field(row, mode)
        if mode == "zt":
            family = (row.get("Pillar") or row.get("pillar") or "Other").strip()
            family_scores[family]["total"] += 1
            overall["total"] += 1
            if status in {"Optimized", "Managed"}:
                family_scores[family]["met"] += 1
                overall["met"] += 1
            continue

        family = (
            row.get("800-171 Family")
            or row.get("Family")
            or row.get("family")
            or "Other"
        ).strip()
        if status == "Not Applicable":
            overall["na"] += 1
            continue
        family_scores[family]["total"] += 1
        overall["total"] += 1
        if status == "Met":
            family_scores[family]["met"] += 1
            overall["met"] += 1
        elif status == "POA&M":
            overall["poam"] += 1

    pct = round((overall["met"] / overall["total"]) * 100, 1) if overall["total"] else 0.0
    title = "CMMC L2 Self-Assessment Report" if mode == "cmmc" else "Zero Trust Maturity Report"
    report: dict[str, Any] = {
        "generated": utc_now_iso(),
        "mode": mode,
        "overall_score_percent": pct,
        "total_controls": overall["total"],
        "met": overall["met"],
        "not_met": overall["total"] - overall["met"],
        "not_applicable": overall["na"],
        "poam_count": overall["poam"],
        "family_breakdown": {
            fam: {
                "met": data["met"],
                "total": data["total"],
                "percent": round((data["met"] / data["total"]) * 100, 1) if data["total"] else 0,
            }
            for fam, data in family_scores.items()
        },
        "recommendation": (
            "Ready for affirmation"
            if overall["total"] and overall["met"] / overall["total"] > 0.85
            else "Complete POA&M items before affirmation or C3PAO"
        ),
    }

    out = output_dir or Path.cwd() / "evidence" / "reports"
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"self_assessment_report_{mode}.json"
    md_path = out / f"self_assessment_report_{mode}.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        f"# {title}",
        "",
        f"Generated: {report['generated']}",
        f"Overall score: **{report['overall_score_percent']}%**",
        f"Met: {report['met']} / {report['total_controls']}",
        f"POA&M items: {report['poam_count']}",
        "",
        "## Family breakdown",
        "",
    ]
    for fam, data in report["family_breakdown"].items():
        lines.append(f"- **{fam}**: {data['percent']}% ({data['met']}/{data['total']})")
    lines.extend(["", f"**Recommendation:** {report['recommendation']}", ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path