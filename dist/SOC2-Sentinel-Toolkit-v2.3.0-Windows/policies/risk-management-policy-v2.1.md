# Risk Management Policy

**Version:** 2.1  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Establish a repeatable process for identifying, assessing, treating, and monitoring information security risks at [ORGANIZATION_NAME]. Supports SOC 2 CC3.x risk activities, NIST 800-171 RA family, and CMMC L2 risk assessment practices.

## Scope

Strategic, operational, technical, vendor, and compliance risks affecting confidentiality, integrity, and availability of customer and organizational data.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Risk Owner (Executive)** | Accepts residual risk above threshold |
| **Security Lead** | Maintains risk register and facilitates assessments |
| **Business Unit Leaders** | Identify domain-specific threats |
| **Compliance** | Maps risks to control frameworks and POA&M items |

## Procedures

1. **Annual risk assessment** inventories assets, threats, vulnerabilities, and existing controls.
2. **Risk scoring** uses likelihood × impact (1–5 scale); scores ≥15 require treatment plan within 30 days.
3. **Risk register** entries include owner, target date, status, and linked controls/policies.
4. **Vendor risk** tiering drives due diligence depth; critical vendors reassessed annually.
5. **Control testing** incorporates automated evidence from SOC2 Sentinel (`run-all` status summary).
6. **Emerging risks** (new product lines, AI features, geopolitical supply chain) trigger ad-hoc review.
7. **Risk acceptance** requires documented business justification and executive sign-off with expiry (≤12 months).
8. **POA&M / remediation tracking** closes findings from collectors with verified retest evidence.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Use in Risk Process | Control Mapping |
|-----------|---------------------|-----------------|
| `iam_access_review` | Orphaned/privileged account risk | CC6.1 / RA |
| `encryption_status` | Data exposure risk quantification | C1.2 |
| `retention_check` | Compliance and legal hold risk | C1.4 |
| `log_aggregator` | Detection capability gaps | CC7.1 |
| `config_drift` | Change and misconfiguration risk | CC6.2 |

Generate consolidated view: `sentinel run-all --provider aws` → import JSON into risk register.

## Review Cadence

- **Full risk assessment:** Annually  
- **Risk register review:** Quarterly  
- **Automated evidence refresh:** Monthly

## CUI / Defense Contractor Notes

Include supply chain and insider threat scenarios for environments processing federal contract information. Map Sentinel `red` status findings to POA&M entries with CMMC practice references. Self-assessment (`sentinel report`) supplements but does not replace formal C3PAO evaluation.

## Related Documents

- `change-management-policy-v2.4.md`
- `monitoring-alerting-policy.md`
- `docs/C3PAO_PREP_30_60_90.md`