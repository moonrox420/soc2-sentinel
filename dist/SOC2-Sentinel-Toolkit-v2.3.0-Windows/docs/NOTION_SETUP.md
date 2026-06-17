# Notion Workspace Setup

Configure a Notion compliance workspace for SOC2 Sentinel controls, evidence, POA&M, CMMC L2, incidents, vendors, and Zero Trust tracking.

> **Disclaimer:** Notion is a documentation tool. This guide does not constitute legal or audit advice. Do not store CUI, live IOCs, or unredacted DIBNet submissions in Notion unless your SSP explicitly authorizes it.

## Overview

Recommended databases:

1. **Controls Matrix** — master SOC 2 / NIST 800-171 catalog
2. **CMMC L2 Controls** — 110 practice tracker
3. **Evidence Log** — collector runs and artifact links
4. **POA&M** — remediation items
5. **Incident Reporting Tracker** — DFARS 7012 incident log
6. **Pre-Assessment Readiness** — C3PAO readiness gates
7. **Vendor Assessment** — supply chain risk records

---

## Database 1: Controls Matrix

### Create the database

1. New page → `/database` → **Table – Full page**
2. Name: **SOC2 Sentinel — Controls Matrix**

### Properties (create exactly)

| Property name | Type | Options / notes |
|---------------|------|-----------------|
| **Control ID** | Title | e.g., CC6.1, C1.2 |
| **TSC Category** | Select | Security, Availability, Confidentiality, Privacy, Processing Integrity |
| **Control Name** | Text | Short name |
| **Description** | Text | Full control description |
| **Related Policy** | Text | Link to policy filename in repo |
| **Key Evidence** | Text | Manual + automated artifacts |
| **Automation Hook** | Select | `iam_access_review`, `log_aggregator`, `config_drift`, `encryption_status`, `retention_check`, `resilience_testing`, `zt_continuous_verification`, Manual |
| **Frequency** | Select | Continuous, Monthly, Quarterly, Annual |
| **Dashboard Status Logic** | Text | Green/yellow/red rules |
| **Defense Notes** | Text | CUI / CMMC context |
| **NIST 800-171 Mapping** | Text | e.g., AC-2, SC-28 |
| **CUI Scope** | Select | Yes, No, Partial |
| **SSP Section Reference** | Text | SSP section ID |
| **800-171 Family** | Select | AC, AT, AU, CM, IA, IR, MA, MP, PE, PS, RA, CA, SC, SI |
| **C3PAO Status** | Select | Ready, In Progress, Gap, Not Applicable |
| **Implementation Statement** | Text | How your org meets the control |
| **CMMC L2 Status** | Select | Met, Not Met, POA&M, Not Applicable |
| **Evidence Strength** | Select | Strong, Moderate, Weak, None |
| **Last Evidence Date** | Date | Updated after each collector run |
| **Sentinel Status** | Select | Green, Yellow, Red, Not Run |
| **Evidence Link** | URL | Path or share link to `report.json` |

### Recommended views

| View name | Type | Filter / sort |
|-----------|------|---------------|
| **All Controls** | Table | Sort by Control ID |
| **CMMC Gaps** | Table | CMMC L2 Status = Not Met or POA&M |
| **By 800-171 Family** | Board | Group by 800-171 Family |
| **Automation Coverage** | Table | Automation Hook is not Manual |
| **CUI In Scope** | Table | CUI Scope = Yes |
| **Red / Yellow** | Table | Sentinel Status = Red or Yellow |

---

## Database 2: CMMC L2 Controls

### Create the database

1. New page → **Table – Full page**
2. Name: **CMMC L2 Controls (110)**

### Properties

| Property | Type | Notes |
|----------|------|-------|
| **Requirement ID** | Title | e.g., 3.1.1 |
| **Family** | Select | Access Control, Awareness and Training, … (14 families) |
| **Requirement Title** | Text | Short title |
| **Full Requirement Text** | Text | Full practice text |
| **CMMC L2 Status** | Select | Met, Not Met, POA&M, Not Applicable |
| **Evidence Strength** | Select | Strong, Adequate, Weak, Missing |
| **Linked SOC2 Control** | Text | e.g., CC6.1 |
| **Automation Hook** | Select | Collector names or Manual |
| **Implementation Statement** | Text | How you meet the practice |
| **Owner** | Person | Control owner |
| **Last Assessment Date** | Date | |
| **SSP Section** | Text | |

### Import

```text
data/notion-import/cmmc-l2-controls.csv
```

Merge on **Requirement ID**.

### Recommended views

| View name | Type | Filter |
|-----------|------|--------|
| **All 110 Practices** | Table | Sort by Requirement ID |
| **By Family** | Board | Group by Family |
| **Not Met** | Table | CMMC L2 Status = Not Met |
| **Automated** | Table | Automation Hook is not Manual |
| **Score Dashboard** | Table | Formula: % Met (manual rollup or linked chart) |

**Score formula tip:** Count Met / (110 − N/A) for self-assessment percentage. Cross-check with `sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc`.

Reference: `docs/CMMC_L2_CONTROLS_REFERENCE.md`

---

## Database 3: Evidence Log

| Property | Type |
|----------|------|
| **Run ID** | Title (date + provider) |
| **Collector** | Select |
| **Control ID** | Relation → Controls Matrix |
| **Provider** | Select: aws, gcp, azure, mock |
| **Status** | Select: green, yellow, red |
| **Collection Timestamp** | Date |
| **Report JSON** | Files & media or URL |
| **Findings Count** | Number |
| **Notes** | Text |

**View:** Calendar on Collection Timestamp; Table filtered to last 30 days.

---

## Database 4: POA&M

| Property | Type |
|----------|------|
| **Finding** | Title |
| **Related Control** | Relation → Controls Matrix |
| **Related CMMC Practice** | Relation → CMMC L2 Controls |
| **Severity** | Select: low, medium, high, critical |
| **Source Collector** | Select |
| **Owner** | Person |
| **Target Date** | Date |
| **Status** | Select: Open, In Progress, Closed, Risk Accepted |
| **Compensating Control** | Text |

Import seed: `data/notion-import/poam-tracker-seed.csv`

---

## Database 5: Incident Reporting Tracker

Track DFARS 252.204-7012 incidents and cyber events. Aligns with `policies/incident-response-policy.md` and `docs/DFARS_7012_INCIDENT_PROCEDURE.md`.

### Properties

| Property | Type | Notes |
|----------|------|-------|
| **Incident ID** | Title | e.g., INC-2026-001 |
| **Detection Date** | Date | UTC — starts 72-hour assessment clock |
| **Incident Type** | Select | Unauthorized access, Malware, Phishing, Data exfiltration, Ransomware, Control failure, Other |
| **Severity** | Select | SEV-1, SEV-2, SEV-3, SEV-4 |
| **DFARS 7012 Applicable** | Select | Yes, No, Under review |
| **CUI Compromised** | Select | Yes, No, Suspected, Unknown |
| **Status** | Select | Open, Contained, Recovering, Closed, Monitoring |
| **Reporting Deadline** | Date | Discovery + 72 hours (if applicable) |
| **External Report Submitted** | Select | Yes (DIBNet), Yes (CO only), No, N/A |
| **DIBNet Reference** | Text | Store redacted confirmation only |
| **Lead Responder** | Person | |
| **Related NIST Controls** | Text | e.g., 3.6.1; 3.14.7 |
| **Legal Sign-off** | Checkbox | Required before external report |
| **Tabletop Related** | Checkbox | If discovered during exercise |
| **Notes** | Text | No live IOCs — reference secure annex |

### Import

```text
data/notion-import/incident-reporting-tracker-seed.csv
```

### Recommended views

| View name | Type | Filter |
|-----------|------|--------|
| **Open Incidents** | Table | Status ≠ Closed |
| **DFARS Applicable** | Table | DFARS 7012 Applicable = Yes |
| **Reporting Deadline** | Calendar | Reporting Deadline |
| **By Severity** | Board | Group by Severity |

Templates: `docs/templates/dibnet-report-template.md`, `docs/templates/tabletop-test-record.md`

---

## Database 6: Pre-Assessment Readiness

C3PAO readiness gates before scheduling assessment.

### Properties

| Property | Type |
|----------|------|
| **Gate ID** | Title | e.g., GATE-01 |
| **Gate Name** | Text | |
| **Phase** | Select | Foundation, Remediation, Validation, Certification |
| **Target Date** | Date | |
| **Status** | Select | Not Started, In Progress, Complete, Blocked |
| **Owner** | Person | |
| **Evidence Required** | Text | |
| **Pass Criteria** | Text | |
| **Blocker Notes** | Text | |

### Import

```text
data/notion-import/pre-assessment-readiness.csv
```

### Recommended views

| View name | Type | Filter |
|-----------|------|--------|
| **Roadmap** | Timeline | Target Date |
| **Blocked** | Table | Status = Blocked |
| **By Phase** | Board | Group by Phase |

Target: ≥85% CMMC L2 Met (excluding justified N/A) before GATE-08.

Reference: `docs/C3PAO_PREP_30_60_90.md`

---

## Database 7: Vendor Assessment

Supply chain risk per `policies/supply-chain-risk-management-policy.md`.

### Properties

| Property | Type |
|----------|------|
| **Vendor Name** | Title | |
| **Service Category** | Select | IaaS, PaaS, SaaS, Professional services, Other |
| **CUI Access Level** | Select | Processes CUI, Metadata only, No CUI, Unknown |
| **Contract Type** | Text | |
| **FedRAMP / SOC2 Status** | Text | |
| **Last Assessment Date** | Date | |
| **Risk Rating** | Select | Low, Medium, High, Critical |
| **Inheritance Documented** | Select | Yes, Partial, No |
| **Key NIST Families** | Text | |
| **Remediation Required** | Select | Yes, No |
| **Next Review Date** | Date | |
| **Questionnaire Link** | URL | Completed `vendor-security-questionnaire.md` |
| **Notes** | Text | |

### Import

```text
data/notion-import/vendor-assessment-seed.csv
```

---

## ATT&CK view (Controls Matrix extension)

Add properties to **Controls Matrix** or create linked **ATT&CK Coverage** database:

| Property | Type |
|----------|------|
| **Technique ID** | Title | e.g., T1078 |
| **Technique Name** | Text | |
| **Tactic** | Select | Persistence, Privilege Escalation, … |
| **Sentinel Component** | Text | Collector name |
| **Detection Value** | Text | |
| **SIEM Rule Exists** | Checkbox | Your org implements |
| **Hunt Scheduled** | Checkbox | Per threat-hunting-playbook |

**Import:** `data/attck-mapping.csv` (create database or merge via script)

**View:** Board grouped by **Tactic**; filter **SIEM Rule Exists** = false for gaps.

Reference: `docs/MITRE_ATTCK_COVERAGE.md`

---

## Zero Trust (ZT) view

Add ZT properties to Controls Matrix or import `data/zero-trust-pillars.csv` as **Zero Trust Pillars** database:

| Property | Type |
|----------|------|
| **Pillar ID** | Title | ZT-01 – ZT-07 |
| **Pillar Name** | Text | User, Device, Network, … |
| **Maturity Level** | Select | Basic, Intermediate, Advanced |
| **Target Maturity** | Select | Basic, Intermediate, Advanced |
| **Linked NIST Controls** | Text | |
| **Sentinel Automation** | Text | |
| **Key Evidence** | Text | |
| **Gaps / Next Steps** | Text | |

### Recommended views

| View name | Type | Filter |
|-----------|------|--------|
| **ZT Maturity Board** | Board | Group by Pillar Name |
| **Below Target** | Table | Maturity Level ≠ Target Maturity |
| **Automation Gaps** | Table | Sentinel Automation contains "Manual" or empty |

Generate report: `sentinel report --input data/zero-trust-pillars.csv --mode zt`

Reference: `docs/ZERO_TRUST_FRAMEWORK.md`

---

## CSV import steps

### Generate / locate CSVs

| File | Source |
|------|--------|
| `data/controls-matrix.csv` | `python scripts/generate_controls_csv.py` |
| `data/notion-import/cmmc-l2-controls.csv` | Included |
| `data/notion-import/poam-tracker-seed.csv` | Included |
| `data/notion-import/incident-reporting-tracker-seed.csv` | Included |
| `data/notion-import/pre-assessment-readiness.csv` | Included |
| `data/notion-import/vendor-assessment-seed.csv` | Included |
| `data/attck-mapping.csv` | Included |
| `data/zero-trust-pillars.csv` | Included |

### Import to Notion

1. Open target database
2. `⋯` menu → **Merge with CSV**
3. Map columns to properties (add missing Select options first)
4. Choose **Merge** on Title column for updates

### Post-import workflow (monthly)

After `sentinel run-all`:

1. Open each `evidence/<date>/<control>/report.json`
2. Create **Evidence Log** entry
3. Update **Controls Matrix**: Sentinel Status, Last Evidence Date, Evidence Link
4. Update **CMMC L2 Controls** rows linked via Automation Hook
5. Create **POA&M** rows for yellow/red findings
6. Refresh ZT pillar evidence notes if `zt_continuous_verification` ran

---

## Optional: Notion API sync

Custom script can PATCH Notion pages via API using Control ID / Requirement ID as lookup keys. Not included in base toolkit.

---

## Governance

- Restrict edit access to Compliance and Security leads
- Version policy documents in Git; link Notion pages to repo paths
- Immutable evidence in S3 Object Lock / WORM—not Notion alone

---

## Honest limitations

Notion dashboards visualize readiness—they do not satisfy audit evidence requirements on their own. CMMC certification requires C3PAO assessment. DFARS reporting requires Legal and FSO action outside Notion. Seed CSV scores (e.g., 22/110 Met) are illustrative starting points—not your organization's actual certification status.

---

*Notion setup guide version 2.3 — SOC2 Sentinel Toolkit.*