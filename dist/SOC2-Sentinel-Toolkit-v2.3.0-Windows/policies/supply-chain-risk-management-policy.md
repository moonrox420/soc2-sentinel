# Supply Chain Risk Management Policy

**Version:** 1.0  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports NIST 800-171 **3.12.4** (supply chain risk management), CMMC L2/L3 supply chain practices, and NIST 800-172 enhanced supply chain controls. It does not replace FedRAMP authorization review, export control counsel, or prime contractor flow-down negotiation. Not legal advice.

## Purpose

Establish how [ORGANIZATION_NAME] identifies, assesses, monitors, and mitigates cybersecurity risks introduced by suppliers, subcontractors, cloud providers, and SaaS vendors—especially where CUI or CDI may be processed.

## Scope

All third parties that:

- Process, store, or transmit organizational or customer data
- Provide infrastructure on which production or CUI systems depend
- Receive network or administrative access to organizational systems
- Subcontract performance of defense or regulated contracts

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security & Compliance** | Owns vendor risk program and assessment criteria |
| **Procurement / Legal** | Embeds security clauses in contracts; manages DPAs |
| **System Owners** | Identify vendors in their architecture; approve onboarding |
| **Executive Sponsor** | Approves high/critical risk vendor exceptions |
| **All Personnel** | Do not onboard unapproved SaaS for production/CUI without review |

## Risk tiering

| Tier | Criteria | Assessment depth | Review frequency |
|------|----------|------------------|------------------|
| **Tier 1 — Critical** | Processes CUI/CDI; production dependency; admin access | Full questionnaire + SOC 2/FedRAMP review + architecture review | Annual |
| **Tier 2 — High** | Processes confidential data; significant operational dependency | Standard questionnaire + certification review | Annual |
| **Tier 3 — Medium** | Internal business tools; limited data exposure | Abbreviated questionnaire | Every 2 years |
| **Tier 4 — Low** | No organizational or customer data | Lightweight checklist | On change |

## Procedures

1. **No production onboarding** without completed assessment using `docs/templates/vendor-security-questionnaire.md`.
2. **CUI vendors** must document shared responsibility mapping in SSP appendix; FedRAMP or equivalent authorization evaluated for IaaS/PaaS where applicable.
3. **Contract clauses** include: breach notification, DFARS 7012 flow-down (defense contracts), right to audit, data return/deletion, subprocessor disclosure.
4. **Inheritance documentation** records which NIST 800-171 families are provider-inherited vs. customer-implemented.
5. **Customer-side controls** for cloud providers are validated by SOC2 Sentinel collectors (`iam_access_review`, `encryption_status`, `log_aggregator`)—provider attestations alone are insufficient.
6. **Continuous monitoring** re-assesses Tier 1 vendors annually and upon material vendor incident or certification lapse.
7. **Offboarding** requires credential revocation, data export/deletion confirmation, and vendor access removal within 30 days.
8. **Subcontractor flow-down** ensures defense subcontracts include NIST 800-171 / CMMC requirements per prime contract.
9. **Concentration risk** (single vendor dependency) is tracked in risk register with contingency plans.
10. **Exceptions** require executive approval, compensating controls, and POA&M entry with expiry.

## Evidence Hooks (SOC2 Sentinel)

| Activity | Evidence |
|----------|----------|
| Customer-side cloud control validation | Monthly `sentinel run-all` bundles |
| Vendor assessment records | Notion Vendor Assessment DB; `vendor-assessment-seed.csv` |
| Shared responsibility matrix | SSP appendix (manual) |
| Subcontract flow-down clauses | Contract repository (manual) |

**Honest limitation:** Sentinel validates **your** configuration in shared cloud environments. It does not audit vendor data centers, SOC 2 reports, or subcontractor compliance.

## Vendor assessment workflow

1. System owner submits vendor intake (name, service, data classification)
2. Security assigns tier and sends `vendor-security-questionnaire.md`
3. Assessor reviews SOC 2 / FedRAMP / ISO evidence under NDA
4. Risk score calculated (Section J of questionnaire)
5. Decision: Approve / Conditional / Deny — recorded in Vendor Assessment tracker
6. POA&M for conditional approvals with due dates

Seed data: `data/notion-import/vendor-assessment-seed.csv`

## Incident and breach coordination

When a vendor reports a security incident affecting your data:

1. Open internal incident per `policies/incident-response-policy.md`
2. Assess CUI/CDI impact with Legal
3. Determine DFARS 7012 reporting obligations **for your organization** independently of vendor notifications
4. Document in Incident Reporting Tracker

## Review Cadence

- **Policy review:** Annually  
- **Tier 1 vendor re-assessment:** Annual  
- **Vendor inventory accuracy:** Quarterly  
- **Supply chain risk register update:** Quarterly

## CUI / Defense Contractor Notes

Defense contractors must manage supply chain risk across primes, subs, and cloud service providers. Map assessments to CMMC practices in `docs/CMMC_L2_CONTROLS_REFERENCE.md` and enhanced controls in `docs/NIST_800_172_CROSSWALK.md`.

Do not claim full supply chain compliance based on vendor marketing materials or incomplete questionnaires.

## Related Documents

- `docs/templates/vendor-security-questionnaire.md`
- `docs/NIST_800_172_CROSSWALK.md`
- `docs/NOTION_SETUP.md` — Vendor Assessment database
- `risk-management-policy-v2.1.md`
- `access-control-policy-v2.3.md`
- `policies/incident-response-policy.md`