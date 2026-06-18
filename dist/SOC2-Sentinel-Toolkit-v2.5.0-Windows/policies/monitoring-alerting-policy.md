# Monitoring & Alerting Policy

**Version:** 1.0  
**Owner:** Security Operations  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Define how [ORGANIZATION_NAME] detects, alerts on, and escalates security-relevant events. Supports SOC 2 CC7.2/CC7.3 incident detection criteria and NIST 800-171 SI-4 system monitoring requirements.

## Scope

SIEM rules, cloud-native alerts, uptime monitors, anomaly detection, on-call rotations, and customer-facing status communications for security incidents.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **SOC Lead** | Defines alert severity matrix and escalation paths |
| **On-call Engineer** | Acknowledges alerts within SLA; initiates runbooks |
| **Incident Commander** | Declares incidents; coordinates DFARS 7012 reporting if applicable |
| **Management** | Receives executive notifications for SEV-1 events |

## Procedures

1. **Alert taxonomy** uses four tiers: Critical (immediate page), High (15 min), Medium (4 hr), Low (next business day).
2. **Critical alerts** include: unauthorized privileged access, encryption disabled on confidential stores, logging pipeline failure >4 hours, and confirmed malware.
3. **Runbooks** exist for each Critical and High alert class; untested runbooks are flagged quarterly.
4. **On-call coverage** is 24×7 for production; backup responder assigned for holidays.
5. **Alert tuning** reviews false-positive rate monthly; rules with >40% false positives are refined or disabled.
6. **Correlation** links cloud audit logs (`log_aggregator`), IAM changes (`iam_access_review`), and app signals.
7. **Post-incident** reviews document detection gaps and new alert requirements within 10 business days.
8. **Customer notification** follows contractual timelines when tenant data may be affected.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `log_aggregator` | `critical_control_failures_30d`, findings array | CC7.2 — anomaly and failure detection |
| `config_drift` | `issues`, `warnings` | CC7.2 — configuration-based alerts |
| `encryption_status` | Unencrypted resource findings | CC7.2 — data protection alerts |

Run full sweep: `sentinel run-all --provider mock` then remediate `red`/`yellow` statuses.

## Review Cadence

- **Alert effectiveness review:** Monthly  
- **Escalation path test:** Quarterly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Organizations subject to DFARS 252.204-7012 must report cyber incidents affecting CUI within 72 hours to DIBNET. Monitoring policies should reference the separate Incident Response procedure. Automated collectors identify control failures—they do not replace contractual incident reporting obligations.

## Related Documents

- `system-monitoring-policy-v2.0.md`
- `risk-management-policy-v2.1.md`
- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`