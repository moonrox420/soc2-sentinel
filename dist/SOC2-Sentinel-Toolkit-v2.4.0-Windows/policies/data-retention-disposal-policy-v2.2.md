# Data Retention & Disposal Policy

**Version:** 2.2  
**Owner:** Legal & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Define how long [ORGANIZATION_NAME] retains information and how it is securely destroyed when no longer needed. Supports SOC 2 C1.4/P4.x privacy elements, NIST 800-171 MP-6, and contractual data handling requirements.

## Scope

Production databases, object storage, backups, logs, endpoints, paper records, and third-party subprocessors.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Legal / Compliance** | Defines statutory and contractual retention schedules |
| **Data Owners** | Approve retention periods per dataset |
| **IT Operations** | Implements lifecycle rules and secure wipe procedures |
| **HR** | Employee record retention and offboarding data handling |

## Procedures

1. **Retention schedule** document lists data categories, minimum retention, maximum retention, and legal basis.
2. **Default maximum** for customer operational data: per contract unless law requires longer retention.
3. **Legal hold** suspends automated deletion; holds tracked in case management system.
4. **Automated enforcement** via S3/GCS/Azure lifecycle policies; gaps detected by `retention_check`.
5. **Log retention** minimum 365 days for security logs; application logs per tiered schedule.
6. **Secure disposal** methods: cryptographic erase for encrypted media, NIST 800-88 clearing for drives, certified shredding for paper.
7. **Vendor disposal** requires certificate of destruction or contractual attestation.
8. **Annual attestation** confirms no datasets exceed maximum retention without documented exception.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `retention_check` | `objects_past_retention`, lifecycle findings | C1.4 |
| `encryption_status` | Ensures disposed media was encrypted pre-wipe | C1.2 |
| `iam_access_review` | Accounts with bulk-delete permissions | CC6.1 |

Command: `sentinel run retention_check --provider aws --control-id C1.4`

## Review Cadence

- **Lifecycle compliance scan:** Monthly  
- **Retention schedule review:** Annually  
- **Legal hold audit:** Quarterly

## CUI / Defense Contractor Notes

CUI disposal must prevent reconstruction and comply with NARA and contract-specific schedules. Buckets without lifecycle rules flagged by Sentinel require immediate policy implementation. This template does not interpret federal recordkeeping obligations—consult Legal for authoritative retention periods.

## Related Documents

- `data-classification-policy-v2.0.md`
- `backup-recovery-policy-v2.2.md`
- `docs/NIST_800_171_CROSSWALK.md` (MP family)