# Access Control Policy

**Version:** 2.3  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee SOC 2, CMMC, or NIST 800-171 certification.

## Purpose

Define how [ORGANIZATION_NAME] grants, reviews, modifies, and revokes access to information systems and data. This policy supports SOC 2 CC6.1, NIST 800-171 AC family controls, and CMMC Level 2 access requirements.

## Scope

Applies to all employees, contractors, vendors, and automated service accounts with access to production systems, customer data, CUI (where applicable), and administrative consoles across AWS, GCP, Azure, SaaS platforms, and on-premises assets.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security Lead** | Owns policy, approves exceptions, reviews quarterly evidence |
| **IT / Platform Engineering** | Implements least-privilege IAM, removes stale access |
| **Managers** | Approve role-based access requests for direct reports |
| **All Personnel** | Use assigned credentials only; report unauthorized access |

## Procedures

1. **Access requests** must be submitted via the approved ticketing system with business justification, data classification, and requested role.
2. **Provisioning** follows least privilege and separation of duties. Default-deny applies to production unless explicitly approved.
3. **Joiner/mover/leaver (JML)** processes revoke access within 24 hours of termination and within 5 business days of role change.
4. **Quarterly access reviews** validate all privileged and production accounts. Owners certify or request removal.
5. **Orphaned accounts** (inactive >90 days) are disabled pending manager confirmation.
6. **Shared and break-glass accounts** require named custodians, MFA, and post-use review within 24 hours.
7. **Third-party access** requires vendor risk review, time-bound credentials, and contract security clauses.
8. **Exceptions** are documented with compensating controls, expiry date, and Security Lead approval.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Artifact | Control Mapping |
|-----------|----------|-----------------|
| `iam_access_review` | `iam_users_export.csv`, JSON evidence bundle | CC6.1 — logical access reviews |
| `config_drift` | MFA and weak-auth metrics | CC6.2 — authentication configuration |

Run: `sentinel run iam_access_review --provider aws` or `sentinel run-all --provider mock` for baseline validation.

## Review Cadence

- **Policy review:** Annually or upon material architecture change  
- **Access certification:** Quarterly  
- **Evidence collection:** Monthly minimum; weekly for high-risk environments

## CUI / Defense Contractor Notes

Organizations handling CUI under DFARS 252.204-7012 must map AC controls to CMMC L2 practices. Privileged access to environments storing CUI requires enhanced logging and documented need-to-know. Coordinate with your C3PAO or internal assessor before relying solely on automated collectors for assessment evidence.

## Related Documents

- `privileged-access-policy-v2.2.md`
- `authentication-access-policy-v2.1.md`
- `docs/NIST_800_171_CROSSWALK.md` (AC family)