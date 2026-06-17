# Business Continuity Policy

**Version:** 1.0  
**Owner:** Executive Operations  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Maintain [ORGANIZATION_NAME] essential functions during disruptions including outages, natural disasters, pandemics, and cyber incidents. Aligns with SOC 2 A1 availability trust criteria and NIST 800-171 contingency planning practices.

## Scope

People, facilities, technology, third-party dependencies, and customer communication for all business-critical processes.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Executive Sponsor** | Declares continuity activation; approves resource allocation |
| **BC Coordinator** | Maintains BCP, conducts tabletop exercises |
| **IT / Security** | Executes technical recovery per DR runbooks |
| **HR / Facilities** | Workforce safety and alternate work arrangements |

## Procedures

1. **Business impact analysis (BIA)** identifies critical processes, dependencies, RTO/RPO, and minimum staffing annually.
2. **Continuity plans** document alternate processing sites, cloud region failover, and manual workarounds.
3. **Crisis communication** templates cover employees, customers, regulators, and insurers.
4. **Tabletop exercises** occur at least annually; full technical failover test every 24 months for tier-1 services.
5. **Vendor continuity** clauses require SLAs and DR evidence from critical SaaS and cloud providers.
6. **Cyber incident integration** links BCP activation to Incident Response and DFARS reporting procedures where applicable.
7. **Plan maintenance** updates within 30 days of material org, product, or infrastructure change.
8. **Evidence retention** stores exercise reports, attendance, and improvement actions ≥3 years.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Relevance | Control Mapping |
|-----------|-----------|-----------------|
| `log_aggregator` | Validates monitoring during failover drills | CC7.1 / A1 |
| `encryption_status` | DR region encryption parity | C1.2 |
| `retention_check` | Continuity documentation retention | C1.4 |
| `config_drift` | Post-failover configuration baseline | CC6.2 |

Technical readiness check before exercises: `sentinel run-all --provider aws`

## Review Cadence

- **BIA refresh:** Annually  
- **Tabletop exercise:** Annually  
- **Policy review:** Annually or after activation event

## CUI / Defense Contractor Notes

Continuity plans for CUI processing must address alternate processing that maintains NIST 800-171 control inheritance. Defense contractors and regulated SaaS vendors should document how customer data remains protected during region failover. This policy does not satisfy DFARS incident reporting—see `docs/DFARS_7012_INCIDENT_PROCEDURE.md`.

## Related Documents

- `backup-recovery-policy-v2.2.md`
- `risk-management-policy-v2.1.md`
- `docs/EXECUTIVE_SUMMARY_TEMPLATE.md`