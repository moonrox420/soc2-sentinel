from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel.scoring")


@dataclass
class ControlScore:
    control_id: str
    name: str
    category: str
    status: str  # "PASS", "PARTIAL", "FAIL", "NOT_ASSESSED"
    score: float  # 0.0 to 100.0
    evidence_quality: str  # "complete", "partial", "failed", "none"
    findings: list[str] = field(default_factory=list)
    metrics_summary: dict[str, Any] = field(default_factory=dict)
    frameworks: dict[str, str] = field(default_factory=dict)


@dataclass
class FrameworkSummary:
    framework_id: str
    framework_name: str
    overall_score: float  # 0.0 to 100.0
    controls_evaluated: int
    controls_passed: int
    controls_partial: int
    controls_failed: int
    readiness_level: str  # "Audit Ready", "Substantial Compliance", "Remediation Required", "Critical Gaps"
    pillar_scores: dict[str, float] = field(default_factory=dict)
    critical_findings: list[str] = field(default_factory=list)


@dataclass
class ComplianceScorecard:
    timestamp: str
    provider: str
    overall_posture_score: float
    soc2: FrameworkSummary
    nist: FrameworkSummary
    cmmc: FrameworkSummary
    zero_trust: FrameworkSummary
    controls: list[ControlScore] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _read_evidence_dir(evidence_base: Path, date_str: str | None = None) -> tuple[str, dict[str, dict[str, Any]]]:
    """Find and load the latest or specified evidence directory."""
    if not evidence_base.exists():
        return "", {}

    if date_str:
        target_dir = evidence_base / date_str
        if not target_dir.exists() or not target_dir.is_dir():
            return date_str, {}
        chosen_dir = target_dir
    else:
        dirs = [d for d in evidence_base.iterdir() if d.is_dir() and d.name != "manifests"]
        if not dirs:
            return "", {}
        chosen_dir = max(dirs, key=lambda d: d.name)

    evidence_by_collector: dict[str, dict[str, Any]] = {}
    canonical_map = {
        "CC6.1": "iam_access_review",
        "CC6.2": "config_drift",
        "CC7.1": "log_aggregator",
        "C1.2": "encryption_status",
        "C1.4": "retention_check",
        "A1.2": "resilience_testing",
        "ZT-1": "zt_continuous_verification",
    }
    for sub in chosen_dir.iterdir():
        if not sub.is_dir() or sub.name == "manifests":
            continue
        ev_file = sub / "report.json"
        if not ev_file.exists():
            ev_file = sub / "evidence.json"
        if ev_file.exists():
            try:
                data = json.loads(ev_file.read_text(encoding="utf-8"))
                collector = data.get("collector") or data.get("control_id") or sub.name
                evidence_by_collector[collector] = data
                evidence_by_collector[sub.name] = data
                ctrl_id = data.get("control_id")
                if ctrl_id:
                    evidence_by_collector[ctrl_id] = data
                    if ctrl_id in canonical_map:
                        evidence_by_collector[canonical_map[ctrl_id]] = data
                if collector in canonical_map:
                    evidence_by_collector[canonical_map[collector]] = data
            except Exception as exc:
                logger.warning("Failed to load evidence file %s: %s", ev_file, exc)
    return chosen_dir.name, evidence_by_collector


def _eval_iam(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="CC6.1",
            name="IAM & Access Provisioning",
            category="Security",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No IAM access review evidence collected"],
            frameworks={"soc2": "CC6.1", "nist": "AC-2, AC-3", "cmmc": "AC.L2-3.1.1", "zt": "ZT-01"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    orphaned = _safe_int(metrics.get("orphaned_accounts", 0))
    mfa_raw = metrics.get("mfa_enforced_percentage", metrics.get("mfa_enforcement_percent"))
    mfa = _safe_float(mfa_raw, 100.0) if mfa_raw is not None else 100.0
    review_days = metrics.get("days_since_last_review")
    review_days_int = _safe_int(review_days, 0) if review_days is not None else 0

    score = 100.0
    findings = []
    if orphaned > 0:
        deduction = min(30.0, orphaned * 5.0)
        score -= deduction
        findings.append(f"{orphaned} orphaned accounts detected requiring deprovisioning")
    if mfa < 100.0:
        deduction = min(40.0, (100.0 - mfa) * 0.8)
        score -= deduction
        findings.append(f"MFA enforcement is only {mfa:.1f}% (target: 100%)")
    if review_days_int > 90:
        score -= 20.0
        findings.append(f"IAM review overdue ({review_days_int} days since last review, max SLA: 90 days)")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="CC6.1",
        name="IAM & Access Provisioning",
        category="Security",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"orphaned_accounts": orphaned, "mfa_enforced_percentage": mfa, "review_days": review_days_int},
        frameworks={"soc2": "CC6.1", "nist": "AC-2, AC-3", "cmmc": "AC.L2-3.1.1", "zt": "ZT-01"},
    )


def _eval_logging(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="CC7.1",
            name="System Logging & Anomaly Monitoring",
            category="Security",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No log aggregator evidence collected"],
            frameworks={"soc2": "CC7.1", "nist": "AU-2, AU-3, AU-6", "cmmc": "AU.L2-3.3.1", "zt": "ZT-06"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    streams = _safe_int(metrics.get("log_streams_active", metrics.get("active_trails", 1)))
    completeness = _safe_float(metrics.get("critical_events_logged_percentage", metrics.get("log_coverage_percent", 100.0)))
    retention = _safe_int(metrics.get("retention_days", metrics.get("cui_retention_days", 365)))
    gap_hours = _safe_float(metrics.get("longest_gap_hours", metrics.get("max_gap_hours", 0.0)))

    score = 100.0
    findings = []
    if streams == 0:
        score -= 50.0
        findings.append("No active log streams configured")
    if completeness < 95.0:
        score -= min(40.0, (95.0 - completeness) * 1.5)
        findings.append(f"Critical event log completeness is {completeness:.1f}% (target: >=95%)")
    if retention < 365:
        score -= 20.0
        findings.append(f"Audit log retention is {retention} days (SOC2/NIST target: >=365 days)")
    if gap_hours > 24.0:
        score -= 20.0
        findings.append(f"Logging gap of {gap_hours:.1f} hours exceeds 24h continuity threshold")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="CC7.1",
        name="System Logging & Anomaly Monitoring",
        category="Security",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"log_streams": streams, "completeness": completeness, "retention_days": retention},
        frameworks={"soc2": "CC7.1", "nist": "AU-2, AU-3, AU-6", "cmmc": "AU.L2-3.3.1", "zt": "ZT-06"},
    )


def _eval_config_drift(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="CC6.2",
            name="Configuration Baseline & Drift Control",
            category="Security",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No configuration drift evidence collected"],
            frameworks={"soc2": "CC6.2", "nist": "CM-2, CM-3", "cmmc": "CM.L2-3.4.1", "zt": "ZT-04"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    evaluated = _safe_int(metrics.get("resources_evaluated", 10))
    drifted = _safe_int(metrics.get("drifted_resources", metrics.get("config_noncompliant_resources", 0)))
    open_sgs = _safe_int(metrics.get("open_security_groups", metrics.get("open_http_listeners", 0)))
    unapproved = _safe_int(metrics.get("unapproved_changes_detected", metrics.get("unapproved_changes", 0)))

    score = 100.0
    findings = []
    if open_sgs > 0:
        score -= min(40.0, open_sgs * 20.0)
        findings.append(f"{open_sgs} security groups permit unrestricted 0.0.0.0/0 ingress")
    if unapproved > 0:
        score -= min(30.0, unapproved * 15.0)
        findings.append(f"{unapproved} unapproved infrastructure modifications detected")
    if evaluated > 0 and drifted > 0:
        drift_rate = (drifted / evaluated) * 100.0
        score -= min(30.0, drift_rate * 0.5)
        findings.append(f"{drifted}/{evaluated} evaluated resources drifted from compliance baselines ({drift_rate:.1f}%)")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="CC6.2",
        name="Configuration Baseline & Drift Control",
        category="Security",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"resources_evaluated": evaluated, "drifted": drifted, "open_sgs": open_sgs},
        frameworks={"soc2": "CC6.2", "nist": "CM-2, CM-3", "cmmc": "CM.L2-3.4.1", "zt": "ZT-04"},
    )


def _eval_encryption(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="C1.2",
            name="Cryptographic Protection & Key Management",
            category="Confidentiality",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No encryption status evidence collected"],
            frameworks={"soc2": "C1.2", "nist": "SC-8, SC-13, SC-28", "cmmc": "SC.L2-3.13.8", "zt": "ZT-05"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    total = _safe_int(metrics.get("total_confidential_resources", 0))
    enc = _safe_int(metrics.get("encrypted_at_rest", 0))
    if "encrypted_at_rest_percentage" in metrics:
        at_rest = _safe_float(metrics["encrypted_at_rest_percentage"], 100.0)
    elif total > 0:
        at_rest = (enc / total) * 100.0
    else:
        at_rest = 100.0

    in_transit_val = metrics.get("tls_enforced_percentage")
    if in_transit_val is not None:
        in_transit = _safe_float(in_transit_val, 100.0)
    else:
        weak_ciphers = _safe_int(metrics.get("weak_cipher_endpoints", 0))
        in_transit = 100.0 if weak_ciphers == 0 else 50.0

    unencrypted_stores = _safe_int(metrics.get("unencrypted_data_stores", metrics.get("unencrypted_cui_count", 0)))
    fips_val = metrics.get("fips_compliant_algorithms")
    if fips_val is not None:
        fips = bool(fips_val)
    else:
        fips = _safe_int(metrics.get("fips_compliant_keys", 1), 1) > 0

    score = 100.0
    findings = []
    if unencrypted_stores > 0:
        score -= min(50.0, unencrypted_stores * 25.0)
        findings.append(f"{unencrypted_stores} unencrypted storage volumes or databases detected")
    if at_rest < 100.0:
        score -= (100.0 - at_rest) * 0.4
        findings.append(f"Encryption at rest is {at_rest:.1f}% (target: 100%)")
    if in_transit < 100.0:
        score -= (100.0 - in_transit) * 0.4
        findings.append(f"TLS 1.2+ transit enforcement is {in_transit:.1f}% (target: 100%)")
    if not fips:
        score -= 10.0
        findings.append("Cryptographic suites are not verified FIPS 140-2/3 compliant")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="C1.2",
        name="Cryptographic Protection & Key Management",
        category="Confidentiality",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"at_rest_pct": at_rest, "transit_pct": in_transit, "unencrypted_stores": unencrypted_stores},
        frameworks={"soc2": "C1.2", "nist": "SC-8, SC-13, SC-28", "cmmc": "SC.L2-3.13.8", "zt": "ZT-05"},
    )


def _eval_retention(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="C1.4",
            name="Data Retention & Secure Disposal",
            category="Confidentiality",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No retention check evidence collected"],
            frameworks={"soc2": "C1.4", "nist": "MP-7, SI-12", "cmmc": "MP.L2-3.8.7", "zt": "ZT-05"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    past_retention = _safe_int(metrics.get("objects_past_retention", 0))
    buckets = _safe_int(metrics.get("policies_checked", 1))
    compliant = _safe_int(metrics.get("compliant_buckets", 1 if past_retention == 0 else 0))
    deletion_valid = bool(metrics.get("deletion_certificates_valid", True))

    score = 100.0
    findings = []
    if past_retention > 0:
        score -= min(40.0, past_retention * 10.0)
        findings.append(f"{past_retention} objects past retention window awaiting secure deletion")
    if buckets > 0 and compliant < buckets:
        ratio = (compliant / buckets) * 100.0
        score -= (100.0 - ratio) * 0.7
        findings.append(f"{buckets - compliant}/{buckets} data storage locations lack enforced lifecycle retention rules")
    if not deletion_valid:
        score -= 30.0
        findings.append("Data purge certificates or deletion verification receipts are invalid or absent")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="C1.4",
        name="Data Retention & Secure Disposal",
        category="Confidentiality",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"policies_checked": buckets, "compliant_policies": compliant},
        frameworks={"soc2": "C1.4", "nist": "MP-7, SI-12", "cmmc": "MP.L2-3.8.7", "zt": "ZT-05"},
    )


def _eval_resilience(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="A1.2",
            name="Backup Integrity & Disaster Recovery",
            category="Availability",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No resilience testing evidence collected"],
            frameworks={"soc2": "A1.2", "nist": "CP-9, CP-10", "cmmc": "RE.L2-3.11.1", "zt": "ZT-07"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    failed_30d = _safe_int(metrics.get("backup_jobs_failed_30d"), 0)
    success_30d = _safe_int(metrics.get("backup_jobs_success_30d"))

    last_backup_hours = metrics.get("last_backup_hours_ago")
    if "successful_backups_24h" in metrics:
        success_24h = _safe_int(metrics["successful_backups_24h"], 0)
        jobs = _safe_int(metrics.get("backup_jobs_evaluated"), success_24h)
    elif last_backup_hours is not None:
        success_24h = 1 if _safe_float(last_backup_hours, 999.0) <= 24.0 else 0
        jobs = 1
    elif success_30d is not None:
        success_24h = 1 if success_30d > 0 else 0
        jobs = 1
    else:
        success_24h = 0
        jobs = 0

    restore_days = metrics.get("last_restore_test_days_ago")
    if "restore_tested_90d" in metrics:
        restore_tested = bool(metrics["restore_tested_90d"])
    elif restore_days is not None:
        restore_tested = _safe_int(restore_days, 999) <= 90
    else:
        restore_tested = True

    rto_met = bool(metrics.get("rto_target_met", True))
    rpo_met = bool(metrics.get("rpo_target_met", True))

    score = 100.0
    findings = []
    if jobs == 0 or success_24h == 0:
        score -= 40.0
        findings.append("No verified successful backup jobs executed in the last 24 hours")
    elif success_24h < jobs:
        score -= 20.0
        findings.append(f"{jobs - success_24h}/{jobs} backup jobs failed in the last 24-hour cycle")
    if failed_30d > 0:
        score -= min(25.0, failed_30d * 5.0)
        findings.append(f"{failed_30d} backup job failures recorded in 30-day monitoring window")
    if not restore_tested:
        score -= 30.0
        findings.append("Disaster recovery restore test has not been executed within the 90-day SLA window")
    if not rto_met:
        score -= 15.0
        findings.append("Recovery Time Objective (RTO) SLA targets are exceeded in current architecture")
    if not rpo_met:
        score -= 15.0
        findings.append("Recovery Point Objective (RPO) SLA targets exceeded in recovery plan")

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="A1.2",
        name="Backup Integrity & Disaster Recovery",
        category="Availability",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"jobs_evaluated": jobs, "success_24h": success_24h, "restore_tested_90d": restore_tested},
        frameworks={"soc2": "A1.2", "nist": "CP-9, CP-10", "cmmc": "RE.L2-3.11.1", "zt": "ZT-07"},
    )


def _eval_zero_trust(data: dict[str, Any] | None) -> ControlScore:
    if not data:
        return ControlScore(
            control_id="ZT-1",
            name="Zero Trust Continuous Verification",
            category="Security",
            status="NOT_ASSESSED",
            score=0.0,
            evidence_quality="none",
            findings=["No Zero Trust continuous verification evidence collected"],
            frameworks={"soc2": "CC6.1, CC6.2", "nist": "AC-2, IA-2, SC-7", "cmmc": "AC.L2-3.1.3", "zt": "ZT-ALL"},
        )
    metrics = data.get("metrics", {})
    quality = data.get("collection_quality", "unknown")
    composite = data.get("composite_checks", {})

    checks_passed = _safe_int(metrics.get("checks_passed", 0))
    checks_total = _safe_int(metrics.get("checks_total", 0))

    if checks_total > 0:
        score = (checks_passed / checks_total) * 100.0
        findings = []
        if checks_passed < checks_total:
            findings.append(f"{checks_total - checks_passed}/{checks_total} zero trust verification checks failed")
        id_verified = bool(composite.get("iam_review_current", True))
        device_health = bool(composite.get("session_timeout_compliant", True))
        least_priv = bool(composite.get("mfa_enforced", True))
    else:
        id_verified = bool(metrics.get("identity_verified", composite.get("iam_review_current", False)))
        device_health = bool(metrics.get("device_health_checked", composite.get("session_timeout_compliant", False)))
        least_priv = bool(metrics.get("least_privilege_enforced", composite.get("mfa_enforced", False)))
        continuous_mon = bool(metrics.get("continuous_monitoring_active", composite.get("encryption_green", False)))
        raw_maturity = _safe_float(metrics.get("zt_maturity_score", 0.0))

        score = 0.0
        findings = []
        if id_verified:
            score += 25.0
        else:
            findings.append("Continuous dynamic identity verification is not enforced")
        if device_health:
            score += 25.0
        else:
            findings.append("Device posture and endpoint health verification telemetry missing")
        if least_priv:
            score += 25.0
        else:
            findings.append("Just-In-Time / Least Privilege micro-segmentation is not fully enforced")
        if continuous_mon:
            score += 25.0
        else:
            findings.append("Continuous automated behavioral verification is not active")

        if raw_maturity > 0.0 and score == 0.0:
            score = raw_maturity * 25.0

    score = max(0.0, min(100.0, score))
    status = "PASS" if score >= 85.0 else ("PARTIAL" if score >= 50.0 else "FAIL")
    return ControlScore(
        control_id="ZT-1",
        name="Zero Trust Continuous Verification",
        category="Security",
        status=status,
        score=score,
        evidence_quality=quality,
        findings=findings,
        metrics_summary={"identity_verified": id_verified, "device_health": device_health, "least_privilege": least_priv},
        frameworks={"soc2": "CC6.1, CC6.2", "nist": "AC-2, IA-2, SC-7", "cmmc": "AC.L2-3.1.3", "zt": "ZT-ALL"},
    )


def _compute_framework_summary(
    framework_id: str,
    framework_name: str,
    scores: list[ControlScore],
    pillar_mapping: dict[str, list[str]],
) -> FrameworkSummary:
    if not scores:
        return FrameworkSummary(
            framework_id=framework_id,
            framework_name=framework_name,
            overall_score=0.0,
            controls_evaluated=0,
            controls_passed=0,
            controls_partial=0,
            controls_failed=0,
            readiness_level="No Evidence",
            pillar_scores={},
            critical_findings=["No evidence has been collected yet."],
        )

    passed = sum(1 for s in scores if s.status == "PASS")
    partial = sum(1 for s in scores if s.status == "PARTIAL")
    failed = sum(1 for s in scores if s.status in {"FAIL", "NOT_ASSESSED"})
    overall = sum(s.score for s in scores) / len(scores)

    if overall >= 85.0:
        readiness = "Audit Ready"
    elif overall >= 70.0:
        readiness = "Substantial Compliance"
    elif overall >= 50.0:
        readiness = "Remediation Required"
    else:
        readiness = "Critical Gaps"

    pillar_scores: dict[str, float] = {}
    for pillar, c_ids in pillar_mapping.items():
        matched = [s.score for s in scores if s.control_id in c_ids]
        pillar_scores[pillar] = round(sum(matched) / len(matched), 1) if matched else 0.0

    critical_findings: list[str] = []
    for s in scores:
        if s.status in {"FAIL", "PARTIAL"}:
            critical_findings.extend(s.findings)

    return FrameworkSummary(
        framework_id=framework_id,
        framework_name=framework_name,
        overall_score=round(overall, 1),
        controls_evaluated=len(scores),
        controls_passed=passed,
        controls_partial=partial,
        controls_failed=failed,
        readiness_level=readiness,
        pillar_scores=pillar_scores,
        critical_findings=critical_findings[:8],
    )


def compute_compliance_scorecard(
    evidence_base: Path | None = None,
    *,
    date_str: str | None = None,
    provider: str | None = None,
) -> ComplianceScorecard:
    """Evaluate full multi-framework compliance posture against evidence."""
    base = evidence_base or (Path.cwd() / "evidence")
    date_found, evidence_map = _read_evidence_dir(base, date_str)

    detected_provider = provider or "unknown"
    for ev in evidence_map.values():
        if ev.get("provider"):
            detected_provider = ev["provider"]
            break

    ctrl_iam = _eval_iam(evidence_map.get("iam_access_review"))
    ctrl_log = _eval_logging(evidence_map.get("log_aggregator"))
    ctrl_drift = _eval_config_drift(evidence_map.get("config_drift"))
    ctrl_enc = _eval_encryption(evidence_map.get("encryption_status"))
    ctrl_ret = _eval_retention(evidence_map.get("retention_check"))
    ctrl_res = _eval_resilience(evidence_map.get("resilience_testing"))
    ctrl_zt = _eval_zero_trust(evidence_map.get("zt_continuous_verification"))

    all_controls = [ctrl_iam, ctrl_log, ctrl_drift, ctrl_enc, ctrl_ret, ctrl_res, ctrl_zt]

    soc2_summary = _compute_framework_summary(
        "soc2",
        "SOC 2 Type II (Trust Services Criteria)",
        all_controls,
        {
            "Security": ["CC6.1", "CC6.2", "CC7.1", "ZT-1"],
            "Confidentiality": ["C1.2", "C1.4"],
            "Availability": ["A1.2"],
        },
    )

    nist_summary = _compute_framework_summary(
        "nist-800-171",
        "NIST SP 800-171 / 800-172",
        all_controls,
        {
            "Access Control (AC)": ["CC6.1", "ZT-1"],
            "Audit & Accountability (AU)": ["CC7.1"],
            "Configuration Management (CM)": ["CC6.2"],
            "System & Comm Protection (SC)": ["C1.2"],
            "Media Protection (MP)": ["C1.4"],
            "Contingency Planning (CP)": ["A1.2"],
        },
    )

    cmmc_summary = _compute_framework_summary(
        "cmmc-l2",
        "CMMC 2.0 Level 2 (110 Controls)",
        all_controls,
        {
            "Access Control": ["CC6.1", "ZT-1"],
            "Identification & Auth": ["CC6.1", "CC6.2"],
            "Audit & Accountability": ["CC7.1"],
            "System Integrity": ["CC6.2", "CC7.1"],
            "Data Protection": ["C1.2", "C1.4"],
            "Recovery & Resilience": ["A1.2"],
        },
    )

    zt_summary = _compute_framework_summary(
        "zero-trust",
        "CISA Zero Trust Maturity Model",
        all_controls,
        {
            "Identity Pillar": ["CC6.1", "ZT-1"],
            "Device Pillar": ["CC6.2", "ZT-1"],
            "Network / Environment": ["CC6.2", "C1.2"],
            "Application & Workload": ["CC6.2", "CC7.1"],
            "Data Pillar": ["C1.2", "C1.4"],
            "Visibility & Analytics": ["CC7.1"],
            "Automation & Orchestration": ["A1.2", "ZT-1"],
        },
    )

    total_score = round(
        (soc2_summary.overall_score * 0.35)
        + (nist_summary.overall_score * 0.25)
        + (cmmc_summary.overall_score * 0.25)
        + (zt_summary.overall_score * 0.15),
        1,
    )

    return ComplianceScorecard(
        timestamp=datetime.now(timezone.utc).isoformat(),
        provider=detected_provider,
        overall_posture_score=total_score,
        soc2=soc2_summary,
        nist=nist_summary,
        cmmc=cmmc_summary,
        zero_trust=zt_summary,
        controls=all_controls,
    )
