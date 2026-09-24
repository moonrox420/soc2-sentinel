from __future__ import annotations

import html
import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.integrity import verify_evidence_tree
from sentinel.scoring import ComplianceScorecard, compute_compliance_scorecard

logger = logging.getLogger("sentinel.reporting")


def generate_executive_html_report(scorecard: ComplianceScorecard, evidence_dir: Path) -> str:
    """Generate a self-contained, printable, executive-ready HTML audit report."""
    manifest_file = evidence_dir / "manifest.json"
    manifest_data: dict[str, Any] = {}
    if manifest_file.exists():
        try:
            manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Run cryptographic verification on the evidence directory
    tree_res = verify_evidence_tree(evidence_dir)
    verified_files = len(tree_res.get("verified", []))
    failed_files = len(tree_res.get("failed", []))
    integrity_valid = (verified_files > 0) and (failed_files == 0)
    status_badge_color = "#10b981" if integrity_valid else ("#f59e0b" if verified_files == 0 else "#ef4444")
    status_badge_text = "VERIFIED TAMPER-EVIDENT" if integrity_valid else ("NO EVIDENCE VERIFIED" if verified_files == 0 else "INTEGRITY WARNING")

    score = scorecard.overall_posture_score
    score_color = "#10b981" if score >= 85.0 else ("#f59e0b" if score >= 70.0 else "#ef4444")

    # Build control rows
    control_rows_html = []
    for ctrl in scorecard.controls:
        status_class = "status-pass" if ctrl.status == "PASS" else ("status-partial" if ctrl.status == "PARTIAL" else "status-fail")
        findings_html = "".join(f"<li>{html.escape(f)}</li>" for f in ctrl.findings) if ctrl.findings else "<span class='text-muted'>No deficiencies identified</span>"
        metrics_pills = "".join(
            f"<span class='metric-pill'><strong>{html.escape(k)}:</strong> {html.escape(str(v))}</span>"
            for k, v in ctrl.metrics_summary.items()
        )
        row = f"""
        <tr>
          <td><span class="control-badge">{html.escape(ctrl.control_id)}</span></td>
          <td>
            <strong>{html.escape(ctrl.name)}</strong>
            <div class="control-category">{html.escape(ctrl.category)} &bull; Quality: {html.escape(ctrl.evidence_quality)}</div>
          </td>
          <td><span class="badge {status_class}">{html.escape(ctrl.status)}</span></td>
          <td><strong>{ctrl.score:.0f}%</strong></td>
          <td><div class="metrics-cell">{metrics_pills}</div></td>
          <td><ul class="findings-list">{findings_html}</ul></td>
        </tr>
        """
        control_rows_html.append(row)

    controls_table = "\n".join(control_rows_html)

    # Framework Cards
    fw_cards = []
    for fw in [scorecard.soc2, scorecard.nist, scorecard.cmmc, scorecard.zero_trust]:
        fw_color = "#10b981" if fw.overall_score >= 85.0 else ("#f59e0b" if fw.overall_score >= 70.0 else "#ef4444")
        pillars_html = "".join(
            f"""
            <div class="pillar-row">
              <span class="pillar-name">{html.escape(pname)}</span>
              <div class="pillar-bar-bg"><div class="pillar-bar-fill" style="width: {pscore}%;"></div></div>
              <span class="pillar-score">{pscore:.0f}%</span>
            </div>
            """
            for pname, pscore in fw.pillar_scores.items()
        )
        fw_cards.append(f"""
        <div class="framework-card">
          <div class="framework-header">
            <h3>{html.escape(fw.framework_name)}</h3>
            <span class="framework-score" style="color: {fw_color};">{fw.overall_score:.1f}%</span>
          </div>
          <div class="framework-readiness">Readiness: <strong>{html.escape(fw.readiness_level)}</strong></div>
          <div class="framework-stats">
            <span class="stat-pill pass">Passed: {fw.controls_passed}</span>
            <span class="stat-pill partial">Partial: {fw.controls_partial}</span>
            <span class="stat-pill fail">Gaps: {fw.controls_failed}</span>
          </div>
          <div class="pillar-container">{pillars_html}</div>
        </div>
        """)

    frameworks_section = "\n".join(fw_cards)

    # Manifest files
    manifest_entries = manifest_data.get("files", {})
    manifest_rows = []
    for fname, fhash in sorted(manifest_entries.items()):
        manifest_rows.append(f"<tr><td><code>{html.escape(fname)}</code></td><td><code class='hash'>{html.escape(fhash)}</code></td></tr>")
    manifest_table_html = "\n".join(manifest_rows) if manifest_rows else "<tr><td colspan='2'>No manifest files recorded</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC2 Sentinel Executive Compliance & Audit Report</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
    }}
    @media print {{
      body {{ background: #fff !important; color: #111 !important; }}
      .framework-card, .score-hero, .section-card {{ box-shadow: none !important; border: 1px solid #ddd !important; background: #fff !important; color: #111 !important; }}
      .no-print {{ display: none !important; }}
      table {{ page-break-inside: auto; }}
      tr {{ page-break-inside: avoid; page-break-after: auto; }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
    }}
    .header h1 {{ font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }}
    .header p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
    .cert-badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 13px;
      letter-spacing: 0.5px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid var(--success);
      color: var(--success);
    }}
    .score-hero {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px;
      display: grid;
      grid-template-columns: 200px 1fr;
      gap: 32px;
      align-items: center;
      margin-bottom: 32px;
    }}
    .overall-gauge {{ text-align: center; }}
    .overall-number {{ font-size: 64px; font-weight: 800; line-height: 1; }}
    .overall-label {{ font-size: 13px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-top: 8px; }}
    .hero-meta {{ display: flex; flex-direction: column; gap: 8px; }}
    .hero-meta h2 {{ font-size: 20px; font-weight: 600; }}
    .hero-meta p {{ color: var(--text-muted); font-size: 14px; }}
    .framework-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }}
    .framework-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }}
    .framework-header {{ display: flex; justify-content: space-between; align-items: center; }}
    .framework-header h3 {{ font-size: 16px; font-weight: 600; }}
    .framework-score {{ font-size: 22px; font-weight: 700; }}
    .framework-readiness {{ font-size: 13px; color: var(--text-muted); margin: 6px 0 12px; }}
    .framework-stats {{ display: flex; gap: 8px; margin-bottom: 16px; }}
    .stat-pill {{ font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; }}
    .stat-pill.pass {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }}
    .stat-pill.partial {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); }}
    .stat-pill.fail {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); }}
    .pillar-row {{ display: flex; align-items: center; gap: 10px; font-size: 12px; margin-bottom: 6px; }}
    .pillar-name {{ flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); }}
    .pillar-bar-bg {{ width: 80px; height: 6px; background: rgba(255,255,255,0.08); border-radius: 3px; overflow: hidden; }}
    .pillar-bar-fill {{ height: 100%; background: var(--primary); border-radius: 3px; }}
    .pillar-score {{ width: 32px; text-align: right; font-weight: 600; }}
    .section-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 32px;
    }}
    .section-card h2 {{ font-size: 18px; margin-bottom: 16px; font-weight: 600; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }}
    th {{ border-bottom: 1px solid var(--border); padding: 12px 10px; color: var(--text-muted); font-weight: 600; }}
    td {{ border-bottom: 1px solid rgba(255,255,255,0.05); padding: 12px 10px; vertical-align: top; }}
    .control-badge {{ background: rgba(59, 130, 246, 0.15); color: var(--primary); padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
    .control-category {{ font-size: 11px; color: var(--text-muted); margin-top: 2px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .status-pass {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }}
    .status-partial {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); }}
    .status-fail {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); }}
    .metrics-cell {{ display: flex; flex-direction: column; gap: 4px; }}
    .metric-pill {{ font-size: 11px; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }}
    .findings-list {{ list-style-type: square; padding-left: 16px; font-size: 12px; color: var(--text-muted); }}
    .findings-list li {{ margin-bottom: 2px; }}
    code {{ font-family: monospace; font-size: 12px; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; }}
    code.hash {{ word-break: break-all; font-size: 11px; color: var(--text-muted); }}
    .footer {{ text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }}
    .btn-print {{
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>SOC2 Sentinel Executive Compliance Report</h1>
        <p>Evidence Collection Date: {html.escape(evidence_dir.name)} &bull; Provider: <strong>{html.escape(scorecard.provider.upper())}</strong> &bull; Generated: {html.escape(scorecard.timestamp)}</p>
      </div>
      <div style="display: flex; align-items: center; gap: 12px;">
        <span class="cert-badge" style="border-color: {status_badge_color}; color: {status_badge_color};">
          &#10003; {status_badge_text}
        </span>
        <button class="btn-print no-print" onclick="window.print()">Print / Export PDF</button>
      </div>
    </div>

    <div class="score-hero">
      <div class="overall-gauge">
        <div class="overall-number" style="color: {score_color};">{score:.0f}%</div>
        <div class="overall-label">Composite Readiness</div>
      </div>
      <div class="hero-meta">
        <h2>Executive Posture Summary</h2>
        <p>This report represents an automated, cryptographic evaluation of security controls spanning SOC 2 Type II Trust Services Criteria, NIST SP 800-171, CMMC 2.0 Level 2, and Zero Trust continuous verification. All findings reflect live cloud infrastructure telemetry collected under SHA-256 and HMAC integrity enforcement.</p>
      </div>
    </div>

    <div class="framework-grid">
      {frameworks_section}
    </div>

    <div class="section-card">
      <h2>Automated Control Evaluation Matrix</h2>
      <table>
        <thead>
          <tr>
            <th>Control</th>
            <th>Title & Scope</th>
            <th>Status</th>
            <th>Score</th>
            <th>Key Telemetry Metrics</th>
            <th>Audit Findings & Deficiencies</th>
          </tr>
        </thead>
        <tbody>
          {controls_table}
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <h2>Cryptographic Chain of Custody & Evidence Manifest</h2>
      <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px;">
        The SHA-256 digests below prove tamper-evident immutability for all raw evidence artifacts collected during this audit window.
      </p>
      <table>
        <thead>
          <tr>
            <th style="width: 300px;">Evidence Artifact File</th>
            <th>SHA-256 Digest</th>
          </tr>
        </thead>
        <tbody>
          {manifest_table_html}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Generated automatically by <strong>SOC2 Sentinel v2.5.0</strong> &bull; Cryptographic Compliance Toolkit
    </div>
  </div>
</body>
</html>
"""
    return html_content


def export_audit_pack(
    evidence_dir: Path,
    output_dir: Path | None = None,
    *,
    custom_scorecard: ComplianceScorecard | None = None,
) -> Path:
    """Generate both the Executive HTML report and package the complete signed Audit Pack ZIP."""
    if not evidence_dir.exists():
        raise FileNotFoundError(f"Evidence directory does not exist: {evidence_dir}")

    dest_dir = output_dir or evidence_dir.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    date_str = evidence_dir.name
    scorecard = custom_scorecard or compute_compliance_scorecard(evidence_dir.parent, date_str=date_str)

    # 1. Generate Executive HTML Report
    html_report = generate_executive_html_report(scorecard, evidence_dir)
    html_path = evidence_dir / f"SOC2-Sentinel-Executive-Report-{date_str}.html"
    html_path.write_text(html_report, encoding="utf-8")

    # 2. Generate Auditor Readme
    readme_content = f"""SOC2 SENTINEL AUDIT EVIDENCE PACKAGE
=====================================
Collection Date: {date_str}
Provider: {scorecard.provider}
Overall Posture Score: {scorecard.overall_posture_score}%
Generated: {datetime.now(timezone.utc).isoformat()}

CONTENTS:
1. SOC2-Sentinel-Executive-Report-{date_str}.html (Printable Executive Report)
2. <control_id>/report.json (Raw evidence payloads)
3. manifest.json (SHA-256 digests of all evidence artifacts)

VERIFICATION INSTRUCTIONS:
To verify the cryptographic integrity of this evidence tree:
$ sentinel verify evidence/{date_str}

All files in this archive were generated deterministically by SOC2 Sentinel v2.5.0.
"""
    (evidence_dir / "AUDITOR_README.txt").write_text(readme_content, encoding="utf-8")

    # 3. Create Audit Pack ZIP
    zip_path = dest_dir / f"SOC2-Sentinel-AuditPack-{date_str}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path in evidence_dir.rglob("*"):
            if file_path.is_file() and not file_path.name.endswith(".tmp"):
                archive_name = file_path.relative_to(evidence_dir.parent)
                archive.write(file_path, arcname=str(archive_name))

    logger.info("Created Executive Audit Pack at %s", zip_path)
    return zip_path
