# CMMC Level 2 Controls Reference

Summary of **110 NIST SP 800-171 Rev 2 practices** assessed at CMMC Level 2, organized by the **14 control families**.

> **Disclaimer:** This reference supports self-assessment and POA&M planning. CMMC L2 **certification** requires assessment by an authorized C3PAO. A score from `sentinel report` is not a certification. Not legal advice.

## Quick facts

| Metric | Value |
|--------|-------|
| **Total L2 practices** | 110 |
| **Control families** | 14 |
| **Source data** | `data/cmmc-l2-controls-110.csv` |
| **Notion import** | `data/notion-import/cmmc-l2-controls.csv` |
| **Self-assessment CLI** | `sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc` |

**Honest baseline:** The seed CSV ships with **22 practices marked Met** via Sentinel automation hooks. The remaining **88** require manual evidence, policy deployment, or future collector coverage. Your organization's score will differ after customization.

---

## 14 family summary

| # | Family | Code | Practices | Primary intent | Sentinel automation | Toolkit policies / docs |
|---|--------|------|-----------|----------------|---------------------|-------------------------|
| 1 | Access Control | AC | 22 | Limit access to authorized users, transactions, and flows | **Strong** — `iam_access_review`, `config_drift` | `access-control-policy-v2.3.md`, `privileged-access-policy-v2.2.md`, `micro-segmentation-policy.md` |
| 2 | Awareness and Training | AT | 3 | Security awareness and role-based training | **Manual** — LMS exports | Organizational HR process |
| 3 | Audit and Accountability | AU | 9 | Create, protect, review audit records | **Strong** — `log_aggregator`, `retention_check` | `system-monitoring-policy-v2.0.md` |
| 4 | Configuration Management | CM | 9 | Baselines, change control, least functionality | **Partial** — `config_drift` | `change-management-policy-v2.4.md` |
| 5 | Identification and Authentication | IA | 11 | Identify users; authenticate before access | **Partial** — `config_drift`, `iam_access_review` | `authentication-access-policy-v2.1.md` |
| 6 | Incident Response | IR | 3 | Detect, respond, recover | **Partial** — `log_aggregator` signals | `incident-response-policy.md`, `DFARS_7012_INCIDENT_PROCEDURE.md` |
| 7 | Maintenance | MA | 6 | Controlled maintenance tools and media | **Manual** | Patch/maintenance records |
| 8 | Media Protection | MP | 9 | Protect and sanitize media | **Partial** — `encryption_status`, `retention_check` | `data-classification-policy-v2.0.md`, `data-retention-disposal-policy-v2.2.md` |
| 9 | Personnel Security | PS | 2 | Screening and personnel termination | **Manual** — HR | Background check records |
| 10 | Physical Protection | PE | 6 | Limit physical access | **Manual** — provider inheritance | Cloud shared responsibility docs |
| 11 | Risk Assessment | RA | 3 | Assess operational risk | **Partial** — `run-all` summary | `risk-management-policy-v2.1.md` |
| 12 | Security Assessment | CA | 4 | Periodic control assessment | **Partial** — `sentinel report` | `CMMC_L2_SELF_ASSESSMENT.md`, `continuous-verification-procedure.md` |
| 13 | System and Communications Protection | SC | 16 | Boundaries, encryption, network protection | **Partial** — `encryption_status`, `config_drift` | `secure-transmission-policy-v2.1.md`, `micro-segmentation-policy.md` |
| 14 | System and Information Integrity | SI | 7 | Flaw remediation, monitoring, malware protection | **Partial** — `log_aggregator`, `config_drift` | `monitoring-alerting-policy.md` |

---

## Practices by family (requirement IDs)

### 1. Access Control (AC) — 22 practices

`3.1.1` – `3.1.22`

Key themes: authorized access, least privilege, session control, remote access, mobile devices, external connections, publicly accessible systems.

**Automation highlights:** 3.1.1, 3.1.5, 3.1.7, 3.1.8 (via collectors). **Gaps:** CUI flow control (3.1.3), separation of duties (3.1.4), wireless/mobile (3.1.16–3.1.19).

### 2. Awareness and Training (AT) — 3 practices

`3.2.1`, `3.2.2`, `3.2.3`

Security awareness, role-based training, insider threat awareness. **Fully manual** — maintain LMS completion exports.

### 3. Audit and Accountability (AU) — 9 practices

`3.3.1` – `3.3.9`

Log creation, user accountability, log review, failure alerting, clock sync, record protection.

**Automation highlights:** 3.3.1, 3.3.2. **Gaps:** 3.3.3 log event review process, 3.3.4 failure alerts (pair with SIEM).

### 4. Configuration Management (CM) — 9 practices

`3.4.1` – `3.4.9`

Baselines, security configuration settings, change control, least functionality, software restrictions.

**Automation highlights:** 3.4.2 (partial via `config_drift`). **Gaps:** formal baselines, software allowlisting documentation.

### 5. Identification and Authentication (IA) — 11 practices

`3.5.1` – `3.5.11`

Identifier management, authenticator management, MFA, replay-resistant auth, identifier reuse.

**Automation highlights:** 3.5.3 MFA (via `config_drift`). **Gaps:** IdP conditional access exports, password policies.

### 6. Incident Response (IR) — 3 practices

`3.6.1`, `3.6.2`, `3.6.3`

IR capability, reporting, incident response testing.

**Procedure coverage:** `incident-response-policy.md`, `DFARS_7012_INCIDENT_PROCEDURE.md`, `tabletop-test-record.md`.

### 7. Maintenance (MA) — 6 practices

`3.7.1` – `3.7.6`

Controlled maintenance, sanitization, inspection, nonlocal maintenance.

**Fully manual** in Sentinel v2.3.

### 8. Media Protection (MP) — 9 practices

`3.8.1` – `3.8.9`

Media access, marking, storage, transport, sanitization, backup protection.

**Automation highlights:** 3.8.9 backup protection (partial via `resilience_testing`, `encryption_status`).

### 9. Personnel Security (PS) — 2 practices

`3.9.1`, `3.9.2`

Screening and termination procedures. **HR manual evidence.**

### 10. Physical Protection (PE) — 6 practices

`3.10.1` – `3.10.6`

Physical access, monitoring, escort, maintenance logs, emergency power.

**Cloud inheritance** — document provider attestation; office controls manual.

### 11. Risk Assessment (RA) — 3 practices

`3.11.1`, `3.11.2`, `3.11.3`

Periodic risk assessment, vulnerability scanning, vulnerability remediation.

**Gaps:** formal VA tool integration planned; use POA&M for remediation tracking.

### 12. Security Assessment (CA) — 4 practices

`3.12.1` – `3.12.4`

Control assessment plan, assess controls, POA&M, supply chain risk.

**Automation:** `sentinel report`, `supply-chain-risk-management-policy.md`.

### 13. System and Communications Protection (SC) — 16 practices

`3.13.1` – `3.13.16`

Boundary protection, encryption in transit/at rest, network segmentation, DNS, collaborative computing.

**Automation highlights:** 3.13.8, 3.13.11, 3.13.16 (encryption). **Gaps:** full segmentation documentation — see `micro-segmentation-policy.md`.

### 14. System and Information Integrity (SI) — 7 practices

`3.14.1` – `3.14.7`

Flaw remediation, malicious code protection, monitoring, unauthorized use detection.

**Automation highlights:** 3.14.6, 3.14.7 (partial via logging). **Gaps:** EDR central reporting, patch SLAs.

---

## Status workflow

| CMMC L2 Status | Meaning | Action |
|----------------|---------|--------|
| **Met** | Evidence demonstrates practice implementation | Maintain; refresh evidence on schedule |
| **Not Met** | Gap identified | POA&M with owner and date |
| **POA&M** | Compensating control or remediation in progress | Track to closure |
| **Not Applicable** | Practice outside assessment boundary | Document justification in SSP |

## Evidence strength

| Strength | Definition |
|----------|------------|
| **Strong** | Automated collector + policy + recent artifact |
| **Adequate** | Manual process with dated evidence |
| **Weak** | Policy only; no recent evidence |
| **Missing** | No implementation |

---

## Commands

```bash
# Full evidence collection
sentinel run-all --provider aws

# CMMC L2 roll-up from 110-practice CSV
sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc

# Notion-ready import
# data/notion-import/cmmc-l2-controls.csv
```

---

## Pre-assessment gates

See `data/notion-import/pre-assessment-readiness.csv` for readiness gates (boundary, SSP, evidence baseline, POA&M, mock assessment, vendor inheritance, C3PAO engagement).

Target: **≥85% Met** (excluding justified N/A) before C3PAO scheduling — adjust threshold with your advisor.

---

## Related documents

- `docs/CMMC_L2_SELF_ASSESSMENT.md`
- `docs/NIST_800_171_CROSSWALK.md`
- `docs/C3PAO_PREP_30_60_90.md`
- `docs/MASTER_REFERENCE_v2.3.md`
- `policies/continuous-verification-procedure.md`

---

*Reference version 2.3 — SOC2 Sentinel Toolkit.*