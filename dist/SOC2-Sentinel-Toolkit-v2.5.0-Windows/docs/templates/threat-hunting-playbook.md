# Threat Hunting Playbook — Log and IAM Export Queries

**Organization:** [ORGANIZATION_NAME]  
**Owner:** Security Operations  
**Last updated:** [YYYY-MM-DD]  
**Review cadence:** Quarterly

> **Disclaimer:** This playbook provides **hunt hypotheses and query patterns** against exports produced by SOC2 Sentinel collectors and your SIEM. It does not replace a managed SOC, EDR, or 24×7 monitoring service. Hunt results require human validation before incident declaration. Not legal advice.

---

## 1. Purpose

Support CMMC L3 practice **3.11.6e** (threat hunting) and NIST 800-171 **SI-4** monitoring by defining repeatable hunts using:

- `iam_access_review` exports (`iam_users_export.csv`, `report.json`)
- `log_aggregator` completeness and sample event exports
- Optional SIEM correlation (Splunk, Sentinel, Chronicle, etc.)

**Sentinel limitation:** Collectors gather point-in-time configuration evidence. Continuous hunting requires scheduled exports and SIEM ingestion—not `sentinel run-all` alone.

---

## 2. Prerequisites

| Prerequisite | Source |
|--------------|--------|
| Monthly `sentinel run-all` evidence | `evidence/[DATE]/` |
| IAM user/role export | `evidence/[DATE]/CC6.1/iam_users_export.csv` |
| Log coverage report | `evidence/[DATE]/CC7.1/report.json` |
| Baseline IAM snapshot (prior month) | Archived evidence folder |
| ATT&CK mapping reference | `docs/MITRE_ATTCK_COVERAGE.md`, `data/attck-mapping.csv` |

---

## 3. Hunt workflow

```text
1. Select hypothesis (ATT&CK technique or insider threat)
2. Verify log completeness ≥ 95% (log_aggregator) — abort if logging gaps exist
3. Pull IAM export + audit logs for hunt window
4. Run queries below (adapt to your SIEM syntax)
5. Triage hits → open incident ticket if credible
6. Document hunt in Evidence Log / POA&M if systemic gap found
```

---

## 4. Hunt 1 — Orphaned and over-privileged accounts (T1078, T1078.004)

**Hypothesis:** Adversaries or insiders use dormant or over-privileged cloud accounts for persistence.

**Data sources:** `iam_access_review` CSV, CloudTrail `AssumeRole` / `CreateAccessKey`

### IAM export queries (CSV / spreadsheet / Python)

```python
# Run against iam_users_export.csv from evidence bundle
# Flag: no activity > 90 days AND active credentials
import pandas as pd
df = pd.read_csv("iam_users_export.csv")
orphans = df[(df["days_since_last_activity"] > 90) & (df["status"] == "active")]
privileged = df[df["is_privileged"] == True]
print("Orphans:", len(orphans), "Privileged:", len(privileged))
```

### CloudTrail hunt (AWS — adapt field names)

```sql
-- SIEM generic pattern
SELECT userIdentity.arn, eventName, sourceIPAddress, eventTime
FROM cloudtrail
WHERE eventName IN ('CreateAccessKey', 'AttachUserPolicy', 'PutUserPolicy', 'AddUserToGroup')
  AND eventTime > now() - interval '30 days'
ORDER BY eventTime DESC
```

**Escalate if:** New access keys on service accounts; `AdministratorAccess` attached outside change window.

**Maps to:** 3.1.1, 3.1.5, 3.5.1 | CC6.1, CC6.3

---

## 5. Hunt 2 — Logging disabled or weakened (T1562.001)

**Hypothesis:** Attacker or misconfiguration disabled audit logging to evade detection.

**Data sources:** `log_aggregator` findings, CloudTrail `StopLogging`, `DeleteTrail`, S3 bucket policy changes

### Pre-hunt gate

```bash
# Check latest log_aggregator status before hunting
cat evidence/2026-06-17/CC7.1/report.json | jq '.status, .findings'
```

**Do not hunt** if status is `red` — remediate logging first, then re-run collector.

### CloudTrail / config hunt

```sql
SELECT eventName, requestParameters, userIdentity.arn, eventTime
FROM cloudtrail
WHERE eventName IN (
  'StopLogging', 'DeleteTrail', 'PutEventSelectors',
  'PutBucketLogging', 'DeleteBucketLogging',
  'PutBucketPolicy', 'DeleteBucketPolicy'
)
AND eventTime > now() - interval '7 days'
```

**Escalate if:** Logging stopped on CUI-scoped resources; correlate with `config_drift` MFA/TLS findings same window.

**Maps to:** 3.3.4, 3.4.2, 3.14.6 | CC7.1, CC7.2

---

## 6. Hunt 3 — Unusual data access volume (T1530, T1567)

**Hypothesis:** Bulk enumeration or exfiltration from unencrypted or misclassified stores.

**Data sources:** S3/Storage access logs, VPC flow logs (if forwarded to SIEM)

```sql
SELECT bucketName, userIdentity.arn, COUNT(*) AS get_count
FROM s3_access_logs
WHERE operation = 'REST.GET.OBJECT'
  AND eventTime > now() - interval '24 hours'
GROUP BY bucketName, userIdentity.arn
HAVING COUNT(*) > 1000
ORDER BY get_count DESC
```

Cross-reference `encryption_status` findings for same bucket names.

**Escalate if:** High `GetObject` rate on CUI-tagged bucket from unfamiliar principal.

**Maps to:** 3.13.8, 3.14.6 | C1.2, CC7.1

---

## 7. Hunt 4 — MFA and authentication downgrades (T1556)

**Hypothesis:** Authentication controls weakened to enable credential abuse.

**Data sources:** `config_drift` report, IdP audit logs

```bash
# Review config_drift findings for MFA gaps
jq '.findings[] | select(.category == "mfa" or .category == "authentication")' \
  evidence/2026-06-17/CC6.2/report.json
```

```sql
-- IdP / IAM policy changes
SELECT actor, target, changeType, timestamp
FROM identity_audit
WHERE changeType IN ('MFA_DISABLED', 'PASSWORD_ONLY_POLICY', 'CONDITIONAL_ACCESS_REMOVED')
  AND timestamp > now() - interval '14 days'
```

**Escalate if:** MFA removed from privileged group without approved change ticket.

**Maps to:** 3.5.2, 3.5.3 | CC6.2

---

## 8. Hunt 5 — Privileged function execution (T1078.004)

**Hypothesis:** Non-privileged users executed admin functions without approval.

```sql
SELECT userIdentity.arn, eventName, sourceIPAddress, errorCode
FROM cloudtrail
WHERE eventName LIKE '%Admin%' OR eventName IN (
  'CreateUser', 'DeleteUser', 'CreateRole', 'PassRole',
  'RunInstances', 'TerminateInstances', 'ModifyVpcAttribute'
)
AND userIdentity.arn NOT IN (SELECT arn FROM approved_admin_inventory)
AND eventTime > now() - interval '7 days'
```

Compare against quarterly `iam_access_review` privileged inventory.

**Maps to:** 3.1.7, 3.3.2 | CC6.3, CC7.1

---

## 9. Hunt 6 — Geographic and temporal anomalies

**Hypothesis:** Credentials used from impossible travel or off-hours admin activity.

```sql
SELECT userIdentity.arn, sourceIPAddress, geo.country, eventTime
FROM cloudtrail
WHERE eventName IN ('ConsoleLogin', 'AssumeRole')
  AND (hour(eventTime) NOT BETWEEN 6 AND 22 OR geo.country NOT IN ('US', 'CA'))
  AND userIdentity.arn LIKE '%admin%'
  AND eventTime > now() - interval '30 days'
```

Tune country/hour filters to your workforce. High false-positive rate expected—correlate with HR travel and on-call schedules.

**Maps to:** 3.14.7 | CC7.2

---

## 10. Hunt documentation template

| Field | Value |
|-------|-------|
| **Hunt ID** | [HUNT-YYYY-NNN] |
| **Date** | [YYYY-MM-DD] |
| **Hypothesis** | |
| **ATT&CK technique** | |
| **Data sources** | |
| **Log completeness at hunt time** | [% from log_aggregator] |
| **Queries run** | |
| **Hits (credible)** | [0 / N — link to incident] |
| **False positives** | |
| **POA&M created?** | [Y/N] |
| **Analyst** | |

---

## 11. Monthly hunt calendar (suggested)

| Week | Hunt focus | Primary collector |
|------|------------|-------------------|
| 1 | Orphaned / privileged IAM | `iam_access_review` |
| 2 | Logging integrity | `log_aggregator` |
| 3 | Encryption + bulk access | `encryption_status` + storage logs |
| 4 | Auth / MFA drift | `config_drift` |

---

## 12. Honest limitations

| Capability | In scope | Out of scope |
|------------|----------|--------------|
| Point-in-time IAM and config evidence | ✅ Sentinel collectors | |
| Real-time IOC matching | | ❌ Requires EDR/SIEM |
| Automated hunt execution | | ❌ Not in Sentinel CLI v2.3 |
| DFARS incident reporting | | ❌ See IR procedure + Legal |
| UEBA / ML anomaly detection | | ❌ Separate platform |

---

## Related documents

- `docs/MITRE_ATTCK_COVERAGE.md`
- `data/attck-mapping.csv`
- `policies/monitoring-alerting-policy.md`
- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`

---

*Template version 2.3 — SOC2 Sentinel Toolkit.*