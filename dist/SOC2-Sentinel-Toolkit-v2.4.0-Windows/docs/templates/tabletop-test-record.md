# Annual DFARS Tabletop Exercise — Test Record

**Organization:** [ORGANIZATION_NAME]  
**Exercise ID:** [TTX-YYYY-NNN]  
**Exercise date:** [YYYY-MM-DD]  
**Duration:** [X hours]  
**Facilitator:** [NAME, TITLE]  
**Document owner:** Security Operations

> **Disclaimer:** This record template supports DFARS 252.204-7012 preparedness documentation. Completing a tabletop does not satisfy reporting obligations or guarantee incident response effectiveness. Customize scenarios to your environment. Not legal advice.

---

## 1. Exercise objectives

| # | Objective | Met? (Y/N) |
|---|-----------|------------|
| 1 | Validate 72-hour discovery-to-DIBNet reporting timeline | |
| 2 | Confirm roles: IC, Legal, FSO, Security Ops, Executive Sponsor | |
| 3 | Practice CDI/CUI breach scenario with evidence preservation | |
| 4 | Test communication rules (internal vs. external) | |
| 5 | Identify gaps for POA&M entry | |

---

## 2. Participants

| Name | Role | Department | Attendance |
|------|------|------------|------------|
| [NAME] | Incident Commander | Security | [Present / Remote] |
| [NAME] | Legal / Counsel | Legal | |
| [NAME] | FSO / DIBNet coordinator | Security | |
| [NAME] | Security Operations lead | Engineering | |
| [NAME] | Executive Sponsor | Leadership | |
| [NAME] | Contracting / Program Manager | Contracts | |
| [NAME] | IT / Platform Engineering | Engineering | |

**Minimum required:** IC, Legal designee, FSO or delegate, Security Ops, Executive Sponsor.

---

## 3. Scenario inject (customize)

### Baseline scenario (recommended)

> **Inject 1 (T+0):** At 09:15 UTC Monday, `log_aggregator` reports a **red** status: CloudTrail logging disabled on an S3 bucket tagged `data-classification=cui` in the production AWS account. Simultaneously, the SOC receives an alert for unusual `GetObject` volume from an IAM role not seen in the last quarterly `iam_access_review`.

> **Inject 2 (T+2h):** Forensics confirms the IAM role was assumed via a long-lived access key attached to a CI service account. Keys were committed to a build artifact 14 days ago. Legal asks whether DFARS 7012 reporting applies.

> **Inject 3 (T+24h):** Scope assessment finds 2,400 CUI-marked files in the bucket were listed (not confirmed downloaded). Contract FA[REDACTED] includes DFARS 252.204-7012.

> **Inject 4 (T+48h):** Executive asks for customer holding statement. Prime contractor emails requesting incident status per flow-down clause.

### Scenario parameters

| Parameter | Value |
|-----------|-------|
| **Systems in scope** | [AWS account / Azure subscription / hybrid] |
| **CUI boundary** | [Reference SSP section] |
| **Contracts affected** | [List contract numbers] |
| **Simulated SEV level** | SEV-1 |
| **DIBNet submission** | Dry run only — no live submission |

---

## 4. Timeline walkthrough (facilitator notes)

Record actual team responses against the 7-step workflow in `docs/DFARS_7012_INCIDENT_PROCEDURE.md`.

| Step | Expected action | Actual response | Gap? |
|------|-----------------|-----------------|------|
| 1 — Detect & declare | IC notified within 15 min; ticket opened with UTC timestamp | | |
| 2 — Preserve | 90-day log hold initiated; chain of custody started | | |
| 3 — Contain | Credentials revoked; affected role isolated | | |
| 4 — Classify | Legal determines CDI/CUI impact and reporting threshold | | |
| 5 — Report | FSO prepares DIBNet fields using `dibnet-report-template.md` | | |
| 6 — Recover | Clean restore path validated; MFA re-enrollment planned | | |
| 7 — Lessons learned | POA&M items assigned within 10 business days | | |

### 72-hour reporting clock exercise

| Milestone | Target (from discovery) | Team stated deadline | Delta |
|-----------|-------------------------|----------------------|-------|
| Legal engagement | ≤ 4 hours | | |
| Scope assessment draft | ≤ 24 hours | | |
| DIBNet draft complete | ≤ 48 hours | | |
| External submission window | ≤ 72 hours | | |

---

## 5. Decision points tested

| Decision | Team decision | Correct per procedure? | Notes |
|----------|---------------|------------------------|-------|
| Declare SEV-1? | | | |
| Engage Legal before CO notification? | | | |
| Notify Contracting Officer? | | | |
| Notify prime contractor? | | | |
| Use pre-approved holding statement? | | | |
| Preserve vs. eradicate priority | | | |

---

## 6. Sentinel integration check

| Collector | Used in scenario? | Evidence path referenced? | Gap identified? |
|-----------|-------------------|---------------------------|-----------------|
| `log_aggregator` | [Y/N] | | |
| `iam_access_review` | [Y/N] | | |
| `encryption_status` | [Y/N] | | |
| `config_drift` | [Y/N] | | |

**Honest limitation noted to participants:** Sentinel collectors validate configuration evidence—they do not detect active intrusions or submit DIBNet reports.

---

## 7. Findings and gaps

| # | Finding | Severity | POA&M ID | Owner | Target date |
|---|---------|----------|----------|-------|-------------|
| 1 | [e.g., FSO backup not trained on DIBNet portal] | High | | | |
| 2 | [e.g., No pre-approved CO notification template] | Medium | | | |
| 3 | [e.g., 90-day preservation runbook not tested] | Medium | | | |

---

## 8. Corrective actions

| Action | Owner | Due date | Status |
|--------|-------|----------|--------|
| Update `docs/DFARS_7012_INCIDENT_PROCEDURE.md` with lessons learned | | | |
| Refresh `dibnet-report-template.md` field ownership | | | |
| Schedule next tabletop | | [+12 months] | |

---

## 9. Attestation

We conducted a tabletop exercise covering DFARS 252.204-7012 cyber incident discovery, classification, 72-hour reporting workflow, and DIBNet field preparation (dry run).

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Facilitator | | | |
| Incident Commander | | | |
| Executive Sponsor | | | |

---

## Related documents

- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `docs/templates/dibnet-report-template.md`
- `policies/incident-response-policy.md`
- `data/notion-import/incident-reporting-tracker-seed.csv`

---

*Template version 2.3 — SOC2 Sentinel Toolkit.*