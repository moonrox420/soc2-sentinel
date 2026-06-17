# MITRE ATT&CK Coverage Map

Maps SOC2 Sentinel collectors and toolkit components to **MITRE ATT&CK** tactics and techniques for detection planning, threat hunting, and assessor conversations.

> **Disclaimer:** This map describes **configuration evidence and hunt hypotheses**—not live threat detection coverage. Sentinel does not implement ATT&CK detections. Pair with SIEM, EDR, and manual hunts per `docs/templates/threat-hunting-playbook.md`. Not legal advice.

**Source data:** `data/attck-mapping.csv`

---

## Coverage summary

| Sentinel component | ATT&CK tactics covered | Primary techniques |
|--------------------|------------------------|------------------|
| `iam_access_review` | Persistence, Privilege Escalation, Initial Access | T1078, T1078.002, T1078.004 |
| `config_drift` | Defense Evasion, Credential Access, Impact | T1562.001, T1556, T1565.001 |
| `log_aggregator` | Discovery, Command and Control, Exfiltration | T1087, T1071, T1567 |
| `encryption_status` | Exfiltration, Impact | T1530, T1486 |
| `retention_check` | Impact, Collection | T1485, T1119 |
| `resilience_testing` | Impact | T1486 (ransomware resilience) |
| `zt_continuous_verification` | Multiple (cross-pillar) | Configuration validation |
| `self_assessment_report` | Reconnaissance, Resource Development | T1595, T1588 (governance) |

**Coverage type:** Primarily **preventive configuration validation** and **hunt data preparation**—not real-time technique detection.

---

## Technique mapping by collector

### iam_access_review

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1078 | Valid Accounts | Persistence | Orphaned accounts, standing privilege |
| T1078.004 | Cloud Accounts | Privilege Escalation | Over-privileged IAM roles |
| T1078.002 | Domain Accounts | Initial Access | Stale federated accounts |

**NIST:** 3.1.1, 3.1.5, 3.1.7, 3.5.1 | **SOC2:** CC6.1, CC6.3

### config_drift

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1562.001 | Disable or Modify Tools | Defense Evasion | Disabled logging, weakened MFA/TLS |
| T1556 | Modify Authentication Process | Credential Access | MFA bypass, password-only paths |
| T1565.001 | Stored Data Manipulation | Impact | Encryption removal on data stores |

**NIST:** 3.4.2, 3.5.2, 3.5.3, 3.13.8, 3.13.16 | **SOC2:** CC6.2, CC8.1, C1.2

### log_aggregator

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1087 | Account Discovery | Discovery | Audit logs enable enumeration detection in SIEM |
| T1071 | Application Layer Protocol | Command and Control | Network/app log completeness |
| T1567 | Exfiltration Over Web Service | Exfiltration | Outbound transfer anomalies (requires SIEM rules) |

**NIST:** 3.3.1, 3.3.2, 3.14.6, 3.14.7 | **SOC2:** CC7.1

### encryption_status

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1530 | Data from Cloud Storage | Exfiltration | Unencrypted stores increase impact |
| T1486 | Data Encrypted for Impact | Impact | Backup encryption validates recovery |

**NIST:** 3.13.8, 3.13.11, 3.13.16, 3.8.9 | **SOC2:** C1.2, C1.3, A1.2

### retention_check

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1485 | Data Destruction | Impact | Lifecycle policies and backup hygiene |
| T1119 | Automated Collection | Collection | Log retention gaps impair forensics |

**NIST:** 3.8.3, 3.3.1 | **SOC2:** C1.4, CC7.1

### resilience_testing

| Technique ID | Name | Tactic | Detection value |
|--------------|------|--------|-----------------|
| T1486 | Data Encrypted for Impact | Impact | Backup/restore validation post-ransomware |

**NIST:** 3.8.9 | **SOC2:** A1.2

---

## Tactics not covered by Sentinel v2.3

Requires separate tools and procedures:

| Tactic | Gap | Recommended approach |
|--------|-----|---------------------|
| Execution | No runtime execution monitoring | EDR |
| Lateral Movement | No live network traffic analysis | NDR, SIEM east-west rules |
| Collection | Limited to config evidence | DLP, EDR |
| Exfiltration (active) | No real-time DLP | SIEM + network monitoring |
| Impact (active) | No runtime ransomware detection | EDR, backups tested manually |

Document these gaps in POA&M and `docs/CMMC_L3_OVERVIEW.md` for L3 readiness.

---

## Using ATT&CK in assessments

### For self-assessment / C3PAO prep

1. Import `data/attck-mapping.csv` to Notion ATT&CK view (see `docs/NOTION_SETUP.md`)
2. For each technique, document: **Prevent** (policy/control), **Detect** (SIEM rule or hunt), **Respond** (IR procedure)
3. Link hunts in `threat-hunting-playbook.md` to technique IDs

### For executive reporting

Report **ATT&CK-informed coverage** as:

- **Configuration prevention:** X techniques mitigated by encryption, MFA, logging
- **Detection (SIEM):** Y techniques with active rules (your count)
- **Hunt program:** Z techniques covered by monthly hunts
- **Gaps:** List tactics without coverage

Do not claim "full ATT&CK coverage" from Sentinel alone.

---

## CMMC L3 alignment

Enhanced control **3.11.6e** (threat hunting) expects proactive searches for IOCs and anomalies. Sentinel provides:

- Hunt playbook with ATT&CK-tagged hypotheses
- IAM and log exports as hunt data sources
- `attck-mapping.csv` for traceability

Does **not** provide automated ATT&CK detection rules.

---

## Related documents

- `docs/templates/threat-hunting-playbook.md`
- `data/attck-mapping.csv`
- `policies/monitoring-alerting-policy.md`
- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `docs/ZERO_TRUST_FRAMEWORK.md`

---

*Coverage map version 2.3 — SOC2 Sentinel Toolkit.*