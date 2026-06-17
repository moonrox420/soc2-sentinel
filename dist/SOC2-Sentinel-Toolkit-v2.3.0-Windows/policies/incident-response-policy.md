# Incident Response Policy

**Version:** 1.0  
**Owner:** Security Operations  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness for SOC 2, NIST 800-171 IR family, CMMC L2/L3, and DFARS 252.204-7012 workflows. It is not legal advice. Reporting obligations depend on your contracts and incident facts. SOC2 Sentinel does not detect intrusions or file government reports on your behalf.

## Purpose

Establish how [ORGANIZATION_NAME] prepares for, detects, responds to, and recovers from security incidents—including cyber incidents affecting Covered Defense Information (CDI) or Controlled Unclassified Information (CUI) where DFARS 252.204-7012 applies.

## Scope

All information systems, cloud environments, endpoints, SaaS platforms, and personnel involved in security incident handling. Includes third-party notifications when customer or contract data may be affected.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Incident Commander (IC)** | Declares severity; coordinates response; owns timeline |
| **Security Operations** | Triage, containment, forensics, evidence preservation |
| **Legal / Counsel** | Determines reporting obligations (DIBNet, CO, customers) |
| **Facility Security Officer (FSO)** | Coordinates DIBNet submission when required |
| **Executive Sponsor** | Approves external communications and resource allocation |
| **IT / Platform Engineering** | Implements containment and recovery technical actions |
| **Contracting / Program Management** | Contracting Officer notifications per counsel guidance |
| **All Personnel** | Report suspected incidents immediately; preserve evidence |

## Procedures

1. **Detection sources** include SIEM alerts, EDR, employee reports, customer notifications, and Sentinel control failures (`log_aggregator`, `config_drift`, `encryption_status`).
2. **All suspected incidents** open a ticket with **UTC discovery timestamp**—this starts internal clocks for DFARS 72-hour reporting assessment.
3. **SEV-1 and SEV-2** incidents page the on-call IC and Security Ops within 15 minutes; Legal is engaged for SEV-1 immediately and SEV-2 within 4 hours.
4. **Containment** prioritizes stopping ongoing harm without destroying forensic evidence; isolate before eradicate unless Legal advises otherwise.
5. **Evidence preservation** follows the 90-day minimum hold in `docs/DFARS_7012_INCIDENT_PROCEDURE.md`; chain of custody is documented.
6. **Classification** is performed by IC + Legal using criteria in the DFARS procedure before external reporting.
7. **External reporting** (DIBNet, Contracting Officer, primes/subs) occurs only after Legal approval using `docs/templates/dibnet-report-template.md`.
8. **Recovery** validates restored systems with `encryption_status` and `log_aggregator` before returning to production.
9. **Post-incident review** completes within 10 business days; findings enter POA&M and `data/notion-import/incident-reporting-tracker-seed.csv`.
10. **Annual tabletop** exercises the 72-hour DFARS workflow; record in `docs/templates/tabletop-test-record.md`.

## Severity matrix

| Severity | Criteria | Response SLA | DFARS consideration |
|----------|----------|--------------|---------------------|
| **SEV-1** | Confirmed CDI/CUI breach, ransomware on covered system, active exfiltration | IC + Legal immediate | 72-hour reporting clock likely |
| **SEV-2** | Suspected unauthorized access to CUI environment | Legal within 4 hours | Reporting assessment required |
| **SEV-3** | Security control failure without confirmed unauthorized access | Remediate per POA&M | Report if counsel determines required |
| **SEV-4** | Near-miss, contained reconnaissance, phishing without compromise | Document | Typically no DFARS report |

## Evidence Hooks (SOC2 Sentinel)

| Collector | Role in IR | Limitation |
|-----------|------------|------------|
| `log_aggregator` | Validates audit log availability for investigation | Does not correlate attacks |
| `iam_access_review` | Scopes compromised accounts; post-incident access review | Point-in-time export |
| `config_drift` | Detects MFA/logging downgrades that may indicate compromise | Not real-time |
| `encryption_status` | Confirms encryption on restored data stores | Configuration scan only |

Run post-recovery validation: `sentinel run-all --provider [aws|gcp|azure]`

## Incident reporting tracker

Track all incidents in the Notion **Incident Reporting Tracker** (see `docs/NOTION_SETUP.md`) or equivalent GRC tool. Seed data: `data/notion-import/incident-reporting-tracker-seed.csv`.

Required fields: Incident ID, Detection Date (UTC), Severity, DFARS applicability, CUI compromised (Y/N), Reporting deadline, External report submitted, Lead responder.

## Review Cadence

- **Policy review:** Annually or after material incident  
- **Tabletop exercise:** Annually minimum  
- **Runbook / DIBNet template refresh:** After each tabletop or regulatory change  
- **On-call escalation test:** Quarterly

## CUI / Defense Contractor Notes

DFARS 252.204-7012 requires rapid cyber incident reporting to DoD when qualifying incidents affect covered systems or CDI. This policy references operational detail in:

- `docs/DFARS_7012_INCIDENT_PROCEDURE.md` — classification, 7-step workflow, preservation
- `docs/templates/dibnet-report-template.md` — submission fields
- `docs/templates/tabletop-test-record.md` — annual exercise record

**Honest statement:** Automated collectors support post-incident evidence and control validation. They do not replace a managed SOC, EDR, forensic retainer, or legal interpretation of reporting thresholds.

## Related Documents

- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `docs/templates/dibnet-report-template.md`
- `docs/templates/tabletop-test-record.md`
- `docs/templates/threat-hunting-playbook.md`
- `monitoring-alerting-policy.md`
- `business-continuity-policy.md`
- `risk-management-policy-v2.1.md`