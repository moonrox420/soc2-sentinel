# Data Classification Policy

**Version:** 2.0  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Define how [ORGANIZATION_NAME] classifies, labels, handles, and protects information based on sensitivity. Supports SOC 2 C1 confidentiality criteria, NIST 800-171 MP/SC families, and CMMC L2 media and transmission controls.

## Scope

All data created, received, stored, or transmitted by personnel and systems, including customer data, employee PII, intellectual property, and CUI where applicable.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Data Owners** | Assign classification to datasets and systems |
| **Engineering** | Implements technical controls per classification tier |
| **All Personnel** | Handles data per label; reports misclassification |
| **Legal / Compliance** | Defines regulatory categories (GDPR, HIPAA, CUI, etc.) |

## Procedures

1. **Classification tiers:**
   - **Public** — approved for unrestricted disclosure
   - **Internal** — default for business operations; SSO required
   - **Confidential** — customer data, financials; encryption + access logging required
   - **Restricted** — CUI, regulated health/financial data; enhanced controls and need-to-know
2. **Labeling** applies in repositories, tickets, and shared drives within 30 days of tier assignment.
3. **Handling rules** escalate with tier: Restricted data never on personal devices or unapproved SaaS.
4. **Data inventory** maps systems to classification; reviewed quarterly.
5. **Downgrade/declassification** requires Data Owner and Legal approval with audit trail.
6. **Third-party sharing** requires classification-appropriate DPAs and transfer mechanisms.
7. **Automated discovery** supplements manual inventory; encryption gaps flagged by `encryption_status`.
8. **Training** covers classification annually for all personnel with data access.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `encryption_status` | `unencrypted_cui_count`, resource inventory | C1.2 — confidential data protection |
| `retention_check` | Objects past retention by bucket | C1.4 |
| `iam_access_review` | Access to confidential stores | CC6.1 |

Run: `sentinel run encryption_status --provider aws --control-id C1.2`

## Review Cadence

- **Data inventory review:** Quarterly  
- **Classification training:** Annually  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

CUI must be marked per DoD CUI Registry categories and stored only in authorized enclaves. `unencrypted_cui_count` >0 from Sentinel should trigger immediate remediation and POA&M entry. Marking requirements are contractual—this template does not replace DD Form 254 or agency-specific guidance.

## Related Documents

- `encryption-key-management-policy-v2.3.md`
- `data-retention-disposal-policy-v2.2.md`
- `docs/NIST_800_171_CROSSWALK.md` (MP / SC families)