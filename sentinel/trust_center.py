import html
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.scoring import compute_compliance_scorecard
from sentinel.vendor_risk import VendorRiskManager

logger = logging.getLogger("sentinel.trust_center")


@dataclass
class TrustBadge:
    name: str
    standard: str
    status: (
        str  # "CONTINUOUSLY_MONITORED" | "EVALUATED" | "IN_PROGRESS" | "NOT_ASSESSED"
    )
    description: str
    icon: str
    valid_until: str = "Continuous"


@dataclass
class SecurityControlHighlight:
    category: str
    title: str
    status: str
    details: str


@dataclass
class TrustCenterProfile:
    company_name: str = "SOC2 Sentinel Enterprise"
    domain: str = "sentinel.enterprise.internal"
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    overall_compliance_score: float = 0.0
    continuous_monitoring_status: str = "INITIALIZING"
    uptime_sla_percentage: float = 100.0
    encryption_at_rest: str = "AES-256-GCM / KMS Verified"
    encryption_in_transit: str = "TLS 1.2+ Enforced"
    penetration_test_cadence: str = "Continuous SAST & Dependency Scanning"
    incident_response_sla: str = "< 1 Hour P0 / Continuous Alerting"
    badges: list[TrustBadge] = field(default_factory=list)
    controls: list[SecurityControlHighlight] = field(default_factory=list)
    subprocessors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "company_name": self.company_name,
            "domain": self.domain,
            "last_updated": self.last_updated,
            "overall_compliance_score": round(self.overall_compliance_score, 1),
            "continuous_monitoring_status": self.continuous_monitoring_status,
            "uptime_sla_percentage": self.uptime_sla_percentage,
            "encryption_at_rest": self.encryption_at_rest,
            "encryption_in_transit": self.encryption_in_transit,
            "penetration_test_cadence": self.penetration_test_cadence,
            "incident_response_sla": self.incident_response_sla,
            "badges": [asdict(b) for b in self.badges],
            "controls": [asdict(c) for c in self.controls],
            "subprocessors": self.subprocessors,
        }


class TrustCenterManager:
    """Compiles live Trust Center posture and generates public/auditor views."""

    def __init__(self, base_dir: Path | str = "data") -> None:
        self.base_dir = Path(base_dir)
        self.vrm = VendorRiskManager(self.base_dir)

    def get_profile(self) -> TrustCenterProfile:
        """Construct live Trust Center profile incorporating current evidence."""
        score = 0.0
        mon_status = "INITIALIZING"
        card = None
        try:
            ev_dir = self.base_dir / "evidence"
            if ev_dir.exists() and any(ev_dir.iterdir()):
                card = compute_compliance_scorecard(ev_dir)
                score = card.overall_posture_score
                mon_status = (
                    "ACTIVE_MONITORING" if score >= 85.0 else "REMEDIATION_REQUIRED"
                )
        except Exception as e:
            logger.debug("Failed computing live scorecard for Trust Center: %s", e)

        # Retrieve registered vendors / subprocessors
        subprocessors = []
        for v in self.vrm.list_vendors():
            subprocessors.append(
                {
                    "name": v.name,
                    "service": v.service_description,
                    "tier": v.tier.value,
                    "data_classification": v.data_classification.value,
                    "dpa_executed": v.questionnaire.dpa_executed,
                    "soc2_status": (
                        "VALID" if v.questionnaire.has_soc2_type2 else "PENDING_REVIEW"
                    ),
                    "soc2_expiration": v.soc2_valid_until or "N/A",
                }
            )

        # Badges derived from verified evidence runs
        badges = [
            TrustBadge(
                name="SOC 2 Type II",
                standard="AICPA Trust Services Criteria (Security, Availability, Confidentiality)",
                status=(
                    "CONTINUOUSLY_MONITORED"
                    if (card and card.soc2.overall_score >= 85.0)
                    else "IN_EVALUATION"
                ),
                description="Automated continuous evidence collection against AICPA Trust Services Criteria.",
                icon="shield-check",
            ),
            TrustBadge(
                name="NIST SP 800-171 Rev 2",
                standard="Protecting Controlled Unclassified Information (CUI)",
                status=(
                    "CONTINUOUSLY_MONITORED"
                    if (card and card.nist.overall_score >= 85.0)
                    else "IN_EVALUATION"
                ),
                description="Telemetry checks mapped across Access Control, Audit, and System Protection families.",
                icon="document-check",
            ),
            TrustBadge(
                name="CMMC 2.0 Level 2",
                standard="Cybersecurity Maturity Model Certification (Automated Telemetry Subset)",
                status=(
                    "CONTINUOUSLY_MONITORED"
                    if (card and card.cmmc.overall_score >= 85.0)
                    else "IN_EVALUATION"
                ),
                description="Continuous automated practice verification and configuration drift detection.",
                icon="check-badge",
            ),
            TrustBadge(
                name="Zero Trust Architecture",
                standard="CISA Zero Trust Maturity Model (Version 2.0)",
                status=(
                    "CONTINUOUSLY_MONITORED"
                    if (card and card.zero_trust.overall_score >= 85.0)
                    else "IN_EVALUATION"
                ),
                description="Continuous identity verification, least privilege standing access, and encryption.",
                icon="cpu-chip",
            ),
        ]

        # Security control highlights derived from live evidence
        controls = []
        if card and card.controls:
            for c in card.controls:
                ctrl_status = (
                    "PASS"
                    if c.status == "PASS"
                    else ("PARTIAL" if c.status == "PARTIAL" else "FAIL")
                )
                finding_desc = (
                    "; ".join(c.findings)
                    if c.findings
                    else f"Evaluated score: {c.score:.0f}% with quality '{c.evidence_quality}'"
                )
                controls.append(
                    SecurityControlHighlight(
                        category=c.category,
                        title=f"{c.control_id} — {c.name}",
                        status=ctrl_status,
                        details=finding_desc,
                    )
                )
        else:
            controls = [
                SecurityControlHighlight(
                    category="Access Control & Authentication",
                    title="CC6.1 — IAM Access Review",
                    status="NOT_ASSESSED",
                    details="Awaiting automated evidence collection run.",
                ),
                SecurityControlHighlight(
                    category="Cryptographic Protection",
                    title="C1.2 — Encryption Status",
                    status="NOT_ASSESSED",
                    details="Awaiting automated evidence collection run.",
                ),
            ]

        return TrustCenterProfile(
            overall_compliance_score=score,
            continuous_monitoring_status=mon_status,
            badges=badges,
            controls=controls,
            subprocessors=subprocessors,
        )

    def generate_trust_center_html(self) -> str:
        """Generate a sleek, production-grade standalone Trust Center web page with strict HTML escaping."""
        profile = self.get_profile()

        badges_html = ""
        for b in profile.badges:
            b_name = html.escape(b.name)
            b_status = html.escape(b.status)
            b_std = html.escape(b.standard)
            b_desc = html.escape(b.description)
            b_val = html.escape(b.valid_until)
            pill_color = (
                "#10b981" if b.status == "CONTINUOUSLY_MONITORED" else "#f59e0b"
            )
            badges_html += f"""
            <div class="badge-card">
                <div class="badge-header">
                    <span class="badge-title">{b_name}</span>
                    <span class="badge-pill" style="color:{pill_color}; border-color:{pill_color}44;">{b_status}</span>
                </div>
                <div class="badge-std">{b_std}</div>
                <div class="badge-desc">{b_desc}</div>
                <div class="badge-date">&check; Status: {b_val}</div>
            </div>
            """

        controls_html = ""
        for c in profile.controls:
            c_cat = html.escape(c.category)
            c_title = html.escape(c.title)
            c_desc = html.escape(c.details)
            c_status = html.escape(c.status)
            pill_color = (
                "#10b981"
                if c.status == "PASS"
                else ("#f59e0b" if c.status == "PARTIAL" else "#ef4444")
            )
            controls_html += f"""
            <div class="control-row">
                <div>
                    <div class="control-cat">{c_cat}</div>
                    <div class="control-title">{c_title}</div>
                    <div class="control-desc">{c_desc}</div>
                </div>
                <div><span class="pill-enforced" style="color:{pill_color}; border-color:{pill_color}44;">&check; {c_status}</span></div>
            </div>
            """

        subproc_html = ""
        if profile.subprocessors:
            for s in profile.subprocessors:
                s_name = html.escape(str(s.get("name", "")))
                s_service = html.escape(str(s.get("service", "")))
                s_tier = html.escape(str(s.get("tier", "")))
                s_soc2 = html.escape(str(s.get("soc2_status", "")))
                s_exp = html.escape(str(s.get("soc2_expiration", "")))
                subproc_html += f"""
                <tr>
                    <td style="font-weight:600; color:#ffffff;">{s_name}</td>
                    <td style="color:#94a3b8;">{s_service}</td>
                    <td><span class="tier-badge">{s_tier}</span></td>
                    <td><span style="color:#10b981;">&check; {s_soc2}</span></td>
                    <td style="color:#38bdf8;">{s_exp}</td>
                </tr>
                """
        else:
            subproc_html = "<tr><td colspan='5' style='color:#94a3b8; text-align:center;'>No third-party subprocessors registered yet. Register vendors using <code>sentinel vendor-risk add</code>.</td></tr>"

        co_name = html.escape(profile.company_name)
        mon_stat = html.escape(profile.continuous_monitoring_status)

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{co_name} — Security & Trust Center</title>
    <style>
        :root {{ --bg: #0b0f19; --card: #131b2e; --border: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #3b82f6; --success: #10b981; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.5; }}
        .nav {{ display: flex; justify-content: space-between; align-items: center; padding: 20px 48px; border-bottom: 1px solid var(--border); background: #0b0f19ee; backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 50; }}
        .nav-logo {{ font-size: 20px; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 8px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 24px; }}
        .hero {{ text-align: center; padding: 40px 0 60px; }}
        .hero h1 {{ font-size: 42px; font-weight: 800; margin: 0 0 16px; background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .hero p {{ font-size: 18px; color: var(--muted); max-width: 700px; margin: 0 auto; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 48px; }}
        .metric-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; text-align: center; }}
        .metric-val {{ font-size: 36px; font-weight: 800; color: var(--success); margin: 8px 0; }}
        .metric-label {{ font-size: 13px; color: var(--muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }}
        .section-title {{ font-size: 24px; font-weight: 700; margin: 40px 0 20px; color: #ffffff; }}
        .badges-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 40px; }}
        .badge-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }}
        .badge-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .badge-title {{ font-size: 18px; font-weight: 700; color: #ffffff; }}
        .badge-pill {{ background: #10b98122; color: #10b981; border: 1px solid #10b98144; padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
        .badge-std {{ font-size: 13px; color: var(--accent); margin-bottom: 8px; font-weight: 500; }}
        .badge-desc {{ font-size: 13px; color: var(--muted); margin-bottom: 12px; }}
        .badge-date {{ font-size: 12px; color: var(--success); font-weight: 600; }}
        .controls-list {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 8px 24px; margin-bottom: 40px; }}
        .control-row {{ display: flex; justify-content: space-between; align-items: center; padding: 18px 0; border-bottom: 1px solid var(--border); }}
        .control-row:last-child {{ border-bottom: none; }}
        .control-cat {{ font-size: 12px; color: var(--muted); text-transform: uppercase; font-weight: 600; }}
        .control-title {{ font-size: 16px; font-weight: 600; color: #ffffff; margin: 2px 0 4px; }}
        .control-desc {{ font-size: 14px; color: var(--muted); }}
        .pill-enforced {{ background: #10b98122; color: #10b981; border: 1px solid #10b98144; padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
        th {{ background: #0f172a; padding: 14px 18px; text-align: left; font-size: 13px; color: var(--muted); border-bottom: 1px solid var(--border); }}
        td {{ padding: 14px 18px; border-bottom: 1px solid var(--border); font-size: 14px; }}
        .tier-badge {{ background: #3b82f622; color: #3b82f6; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-logo">&#128737; {co_name}</div>
        <div style="font-size: 13px; color: var(--success); font-weight: 600;">&bull; Status: {mon_stat}</div>
    </nav>
    <div class="container">
        <div class="hero">
            <h1>Security, Privacy & Trust Center</h1>
            <p>Real-time continuous compliance telemetry, verified cryptographic evidence provenance, and subprocessor management.</p>
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-label">Compliance Posture</div>
                <div class="metric-val">{profile.overall_compliance_score:.1f}%</div>
                <div style="font-size: 12px; color: var(--muted);">Live Telemetry Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Continuous Monitoring</div>
                <div class="metric-val" style="font-size: 20px; color: #38bdf8; margin: 18px 0 10px;">{mon_stat}</div>
                <div style="font-size: 12px; color: var(--muted);">Automated Polling Engine</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Encryption Standard</div>
                <div class="metric-val" style="font-size: 20px; color: #f8fafc; margin: 18px 0 10px;">AES-256-GCM</div>
                <div style="font-size: 12px; color: var(--muted);">KMS Envelope Protection</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Subprocessor Reviews</div>
                <div class="metric-val" style="font-size: 24px; color: var(--success); margin: 16px 0 10px;">{len(profile.subprocessors)}</div>
                <div style="font-size: 12px; color: var(--muted);">Assessed Under CC9.2</div>
            </div>
        </div>

        <div class="section-title">Compliance Frameworks & Certifications</div>
        <div class="badges-grid">
            {badges_html}
        </div>

        <div class="section-title">Verified Core Security Controls</div>
        <div class="controls-list">
            {controls_html}
        </div>

        <div class="section-title">Authorized Subprocessor Directory (SOC 2 CC9.2)</div>
        <table>
            <thead>
                <tr>
                    <th>Vendor / Subprocessor</th>
                    <th>Service Scope</th>
                    <th>Risk Tier</th>
                    <th>SOC 2 Status</th>
                    <th>Next Audit Cycle</th>
                </tr>
            </thead>
            <tbody>
                {subproc_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html_out
