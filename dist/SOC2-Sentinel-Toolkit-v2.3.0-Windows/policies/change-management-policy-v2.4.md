# Change Management Policy

**Version:** 2.4  
**Owner:** Engineering Operations  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Ensure changes to [ORGANIZATION_NAME] production systems are authorized, tested, documented, and reversible. Aligns with SOC 2 CC8.1, NIST 800-171 CM family, and CMMC L2 configuration management practices.

## Scope

Infrastructure-as-code, CI/CD pipelines, database schema changes, network rules, SaaS admin configuration, and emergency hotfixes.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Change Advisory (CAB)** | Reviews high-risk changes weekly |
| **Release Manager** | Maintains deployment calendar and freeze windows |
| **Engineers** | Submit change tickets with rollback plans |
| **Security** | Reviews changes affecting auth, encryption, or logging |

## Procedures

1. **Standard changes** (pre-approved, low risk) still require ticket linkage and automated pipeline audit trail.
2. **Normal changes** require peer review, staging validation, and documented rollback steps before production.
3. **Emergency changes** may bypass CAB but require post-implementation review within 48 hours and Security notification.
4. **Segregation of duties:** deployers cannot unilaterally approve their own production security control changes.
5. **Maintenance windows** are published; customer-impacting changes require advance notice per SLA.
6. **Configuration baselines** are stored in version control; drift is detected via `config_drift` collector monthly.
7. **Rollback testing** is required for database migrations and auth changes; metrics tracked in change tickets.
8. **Change records** are retained ≥3 years for audit and linked to deployment commit SHAs.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `config_drift` | `unapproved_changes`, `changes_missing_rollback_test` | CC8.1 / CC6.2 — change control |
| `log_aggregator` | CloudTrail/Config change event coverage | CC7.1 — change audit trail |
| `iam_access_review` | Deploy role inventory | CC6.1 — who can change production |

Example: `sentinel run config_drift --provider aws --control-id CC6.2`

## Review Cadence

- **CAB meeting:** Weekly for high-risk queue  
- **Drift scan:** Monthly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Changes to boundaries protecting CUI require enhanced scrutiny and SSP update when architecture shifts. Defense contractors should correlate Sentinel drift findings with actual change tickets—automation detects symptoms, not approval workflow compliance.

## Related Documents

- `risk-management-policy-v2.1.md`
- `system-monitoring-policy-v2.0.md`
- `docs/C3PAO_PREP_30_60_90.md`