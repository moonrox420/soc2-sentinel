# Privileged Access Policy

**Version:** 2.2  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Control elevated permissions that can alter security configurations, access all tenant data, or disrupt production services. Supports SOC 2 CC6.1/CC6.3, NIST 800-171 AC-2/AC-6, and CMMC L2 privileged access practices.

## Scope

Includes cloud root/owner roles, Kubernetes cluster-admin, database superuser, domain admin, CI/CD deploy keys, and emergency break-glass accounts across all environments.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **CISO / Security Lead** | Approves standing privileged roles |
| **Platform Engineering** | Implements PAM, JIT access, and role boundaries |
| **Auditors / Compliance** | Reviews quarterly privileged access certifications |
| **On-call Engineers** | Use just-in-time elevation; document break-glass usage |

## Procedures

1. **Standing privilege is minimized.** Default engineering access is read-only; elevation is time-bound (≤8 hours).
2. **Privileged role inventory** is maintained and reconciled monthly against IAM exports.
3. **Separation of duties** prevents single individuals from both deploying code and approving production changes without secondary review.
4. **Break-glass accounts** are sealed, monitored, MFA-protected, and reviewed within 24 hours of each use.
5. **Privileged sessions** are logged; cloud admin API calls must appear in centralized logging (`log_aggregator` coverage).
6. **Vendor admin access** requires executive approval, defined scope, and automatic expiry.
7. **Quarterly certification** requires business owners to attest each privileged assignment or request removal.
8. **De-provisioning** removes privileged roles immediately upon role change or termination—no grace period.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Artifact | Control Mapping |
|-----------|----------|-----------------|
| `iam_access_review` | `privileged_count`, per-user privileged flag in CSV | CC6.1 — privileged account review |
| `log_aggregator` | Admin API audit trail coverage | CC7.1 — monitoring privileged activity |

Run: `sentinel run iam_access_review --provider aws` and correlate `privileged_count` with HR roster.

## Review Cadence

- **Privileged inventory reconciliation:** Monthly  
- **Access certification:** Quarterly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Privileged access to CUI-bearing systems should use dedicated admin workstations or hardened jump hosts where feasible. Document all standing privileged roles in your SSP. Defense contractors and regulated SaaS providers should treat any `privileged_count` >0 without documented justification as a finding during self-assessment.

## Related Documents

- `access-control-policy-v2.3.md`
- `system-monitoring-policy-v2.0.md`
- `docs/CMMC_L2_SELF_ASSESSMENT.md`