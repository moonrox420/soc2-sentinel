# Backup & Recovery Policy

**Version:** 2.2  
**Owner:** Platform Engineering  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Ensure [ORGANIZATION_NAME] can restore critical systems and data within defined recovery objectives. Supports SOC 2 A1.2/A1.3 availability criteria and NIST 800-171 CP family contingency planning elements.

## Scope

Production databases, object storage, configuration repositories, secrets vaults, IdP configuration exports, and disaster recovery runbooks.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Platform Lead** | Defines RPO/RTO targets and backup architecture |
| **DBA / Data Engineering** | Validates backup integrity and restore tests |
| **Security** | Ensures backups are encrypted and access-controlled |
| **Compliance** | Archives restore test records for audit periods |

## Procedures

1. **Backup frequency** meets or exceeds RPO: transactional data ≤24 hours; configuration ≤7 days.
2. **Encryption at rest** applies to all backup stores; verified via `encryption_status` collector.
3. **Geographic redundancy** stores copies in a separate region/account from primary production.
4. **Access control** limits backup restore permissions to break-glass roles with MFA and logging.
5. **Restore testing** occurs semi-annually for tier-1 systems; results documented with actual RTO achieved.
6. **Retention alignment** ensures backup lifecycle rules comply with `retention_check` and legal holds.
7. **Immutable backups** (object lock / WORM) protect against ransomware for tier-1 datasets where feasible.
8. **Decommissioning** includes secure destruction of obsolete backup media per data disposal policy.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `encryption_status` | Backup bucket encryption, KMS rotation | C1.2 / A1.2 |
| `retention_check` | Lifecycle rules on backup buckets | C1.4 / A1.3 |
| `iam_access_review` | Restore-role privileged accounts | CC6.1 |

Command: `sentinel run encryption_status --provider aws` focusing on backup S3/RDS snapshots.

## Review Cadence

- **Backup job health review:** Weekly  
- **Restore test:** Semi-annually (tier-1); annually (tier-2)  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Backups containing CUI must remain within authorized geographic boundaries and encryption standards (FIPS 140-validated modules where contractually required). Document backup locations in the SSP. Automated encryption scans identify misconfigured stores—they do not validate restore success.

## Related Documents

- `business-continuity-policy.md`
- `encryption-key-management-policy-v2.3.md`
- `data-retention-disposal-policy-v2.2.md`