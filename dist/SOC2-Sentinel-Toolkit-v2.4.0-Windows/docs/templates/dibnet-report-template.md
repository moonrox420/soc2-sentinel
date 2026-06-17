# DIBNet Cyber Incident Report — Field Template (Redacted)

**Organization:** [ORGANIZATION_NAME]  
**Report prepared by:** [PREPARER_NAME], [TITLE]  
**Report date (UTC):** [YYYY-MM-DD HH:MM UTC]  
**Incident ID (internal):** [INC-YYYY-NNN]

> **Disclaimer:** This template lists commonly requested DIBNet submission fields based on public DoD guidance. Reporting forms, required fields, and submission channels change. Verify current instructions at [https://dibnet.dod.mil](https://dibnet.dod.mil) before submission. SOC2 Sentinel does not file reports on your behalf. This is not legal advice.

> **Security:** Do not store completed reports with operational details in unsecured collaboration tools. Use access-controlled, encrypted storage. Redact sensitive indicators before sharing outside the IR team.

---

## Section 1 — Reporter and organization

| Field | Value (redacted example) |
|-------|--------------------------|
| **Company legal name** | [ORGANIZATION_NAME] |
| **CAGE code** | [XX-XXX] |
| **UEI (if applicable)** | [XXXXXXXXXXXX] |
| **Primary point of contact** | [NAME — title] |
| **24-hour contact phone** | [REDACTED — store in secure contact sheet] |
| **24-hour contact email** | [REDACTED] |
| **Alternate contact** | [NAME — title] |
| **Facility / location affected** | [e.g., US-East cloud region — no street address required in draft] |

---

## Section 2 — Contract and program context

| Field | Value |
|-------|-------|
| **Contract number(s) affected** | [e.g., FAXXXXXXXXXXXX — list all known] |
| **Prime contractor (if subcontractor)** | [PRIME_NAME or N/A] |
| **Program / effort name** | [REDACTED or public program name per counsel] |
| **DFARS 252.204-7012 in contract?** | [Yes / No / Under review] |
| **CUI categories involved** | [e.g., CTI, PRVCY, or "Under determination"] |
| **Covered contractor information system?** | [Yes / No / Under investigation] |

---

## Section 3 — Incident discovery and timeline

| Field | Value |
|-------|-------|
| **Discovery date/time (UTC)** | [YYYY-MM-DD HH:MM UTC] — **72-hour clock starts here per counsel** |
| **Discovery method** | [SIEM alert / EDR / employee report / customer notification / Sentinel control failure] |
| **Earliest suspected compromise (UTC)** | [YYYY-MM-DD HH:MM UTC or Unknown] |
| **Incident declared (internal SEV)** | [SEV-1 / SEV-2 / SEV-3] |
| **Incident Commander** | [NAME] |
| **Legal counsel engaged** | [Yes — DATE/TIME UTC] |

### Timeline (UTC, factual only)

| Time (UTC) | Event |
|------------|-------|
| [T+0h] | [e.g., Alert received — log_aggregator flagged logging gap on CUI-scoped bucket] |
| [T+1h] | [e.g., IC convened; containment initiated] |
| [T+4h] | [e.g., Forensic image captured; credentials rotated] |
| [T+24h] | [e.g., Scope assessment — CDI access [confirmed / not confirmed / under review]] |

---

## Section 4 — Incident classification (DFARS 7012)

Complete with Legal before external submission. See `docs/DFARS_7012_INCIDENT_PROCEDURE.md` for classification criteria.

| Question | Response |
|----------|----------|
| **Qualifies as cyber incident per clause?** | [Yes / No / Pending legal determination] |
| **Affects covered contractor information system?** | [Yes / No / Unknown] |
| **CDI or CUI compromised or exfiltrated?** | [Yes / No / Suspected / Unknown] |
| **Ransomware or destructive malware?** | [Yes / No] |
| **Attribution (if known)** | [Unknown / Nation-state suspected / Criminal / Insider — per counsel only] |
| **Reporting required to DoD?** | [Yes / No — Legal sign-off: _______] |
| **Reporting required to Contracting Officer?** | [Yes / No — Legal sign-off: _______] |
| **Flow-down notification to primes/subs?** | [Yes / No / N/A] |

---

## Section 5 — Technical summary (redacted for draft)

| Field | Value |
|-------|-------|
| **Incident type** | [Unauthorized access / Malware / Phishing / Data exfiltration / Denial of service / Other] |
| **Systems affected** | [e.g., AWS account [REDACTED], production VPC — no hostnames with live IOCs in drafts] |
| **Accounts compromised** | [COUNT — list roles in secure annex] |
| **Data types potentially accessed** | [CDI / CUI / PII / None confirmed] |
| **Estimated records affected** | [NUMBER or Unknown] |
| **Entry vector (suspected)** | [Stolen credentials / Misconfiguration / Supply chain / Unknown] |
| **Persistence mechanisms** | [API keys / IAM roles / Backdoor — secure annex] |
| **Indicators of compromise (IOCs)** | **Store in secure forensic annex — do not paste live IOCs in email** |

### Compensating controls in place at discovery

- [ ] MFA enforced on admin accounts (`config_drift` evidence: [PATH or DATE])
- [ ] Encryption at rest on affected stores (`encryption_status`: [STATUS])
- [ ] Audit logging enabled (`log_aggregator`: [COVERAGE %])

---

## Section 6 — Impact and operational status

| Field | Value |
|-------|-------|
| **Business impact** | [None / Degraded / Halted — describe briefly] |
| **Customer impact** | [None / Notified / Pending notification] |
| **Operations status** | [Contained / Eradication in progress / Recovered / Monitoring] |
| **Estimated recovery date** | [YYYY-MM-DD or Ongoing] |

---

## Section 7 — Response actions taken

| Action | Status | Date (UTC) |
|--------|--------|------------|
| Affected systems isolated | [Done / In progress] | |
| Compromised credentials revoked | [Done / In progress] | |
| Forensic preservation (90-day minimum) | [Done / In progress] | |
| Malware eradication | [Done / N/A / In progress] | |
| Patches / hardening applied | [Done / In progress] | |
| Password/MFA reset for affected users | [Done / In progress] | |
| Enhanced monitoring deployed | [Done / In progress] | |
| Law enforcement notified | [Yes / No / N/A — per counsel] | |

---

## Section 8 — Corrective and preventive actions

| # | Action | Owner | Target date |
|---|--------|-------|-------------|
| 1 | [e.g., Close logging gap on CUI-scoped resources] | [OWNER] | [DATE] |
| 2 | [e.g., Quarterly IAM review acceleration] | [OWNER] | [DATE] |
| 3 | [e.g., IR tabletop findings remediation] | [OWNER] | [DATE] |

Link open items to POA&M and `data/notion-import/incident-reporting-tracker-seed.csv` workflow.

---

## Section 9 — Evidence preservation attestation

| Item | Location | Retention end date |
|------|----------|-------------------|
| Cloud audit logs | [S3/Azure/GCS path — encrypted, access-controlled] | [Discovery + 90 days minimum] |
| EDR timelines | [Vendor export path] | [DATE] |
| Incident tickets and chat | [Ticketing system export] | [DATE] |
| Forensic images | [Evidence locker ID] | [Per legal hold] |
| Sentinel evidence bundles | `evidence/[DATE]/[CONTROL]/report.json` | [DATE] |

**Preservation lead:** [NAME]  
**Chain of custody log:** [REFERENCE — secure repository]

---

## Section 10 — Submission record

| Field | Value |
|-------|-------|
| **DIBNet submission date/time (UTC)** | [YYYY-MM-DD HH:MM UTC] |
| **Submitted by** | [NAME — typically FSO or delegate] |
| **Confirmation / reference number** | [REDACTED — store in incident tracker] |
| **Contracting Officer notified** | [Yes — DATE] |
| **Prime contractor notified** | [Yes / N/A — DATE] |
| **Subcontractors notified (flow-down)** | [Yes / N/A — DATE] |

---

## Approvals (before external submission)

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Incident Commander | | | |
| Legal / Counsel | | | |
| Executive Sponsor | | | |
| FSO (DIBNet submitter) | | | |

---

## Related documents

- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `policies/incident-response-policy.md`
- `docs/templates/tabletop-test-record.md`
- `data/notion-import/incident-reporting-tracker-seed.csv`

---

*Template version 2.3 — SOC2 Sentinel Toolkit. Replace bracketed fields; redact before distribution.*