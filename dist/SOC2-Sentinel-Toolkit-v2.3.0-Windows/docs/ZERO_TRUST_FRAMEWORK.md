# Zero Trust Framework

Implementation guide for Zero Trust Architecture (ZTA) maturity across the **seven pillars**, aligned with NIST SP 800-207 and mapped to SOC2 Sentinel collectors.

> **Disclaimer:** Zero Trust is an architecture strategy—not a product or certification. This framework tracks **maturity progress** using toolkit automation where available. It does not guarantee CMMC, FedRAMP, or SOC 2 outcomes. Not legal advice.

**Source data:** `data/zero-trust-pillars.csv`

---

## Seven pillars overview

| Pillar ID | Pillar | Seed maturity | Target | Primary collectors |
|-----------|--------|---------------|--------|-------------------|
| **ZT-01** | User | Intermediate | Advanced | `iam_access_review`, `config_drift` |
| **ZT-02** | Device | Basic | Intermediate | `config_drift` (partial) |
| **ZT-03** | Network / Environment | Intermediate | Advanced | `config_drift`, `log_aggregator` |
| **ZT-04** | Application and Workload | Intermediate | Advanced | `config_drift` |
| **ZT-05** | Data | Advanced | Advanced | `encryption_status`, `retention_check` |
| **ZT-06** | Visibility and Analytics | Intermediate | Advanced | `log_aggregator`, `self_assessment_report` |
| **ZT-07** | Automation and Orchestration | Intermediate | Advanced | `run-all` CLI, `self_assessment_report` |

Generate maturity report:

```bash
sentinel report --input data/zero-trust-pillars.csv --mode zt
```

---

## Pillar details

### ZT-01 — User

**Principle:** Verify every user identity; enforce least privilege and MFA.

| Control area | NIST 800-171 | Evidence |
|--------------|--------------|----------|
| IAM inventory | 3.1.1, 3.1.5 | `iam_access_review` quarterly export |
| MFA enforcement | 3.5.2, 3.5.3 | `config_drift` MFA metrics |
| Privileged access | 3.1.7 | `iam_access_review` privileged flags |

**Gaps (seed):** Hardware MFA for break-glass; IdP conditional access export not automated.

**Policies:** `access-control-policy-v2.3.md`, `authentication-access-policy-v2.1.md`, `privileged-access-policy-v2.2.md`

### ZT-02 — Device

**Principle:** Verify device health before granting access.

| Control area | Evidence |
|--------------|----------|
| MDM enrollment | Manual policy checklist |
| Endpoint encryption | Manual attestation |

**Honest gap:** No MDM posture collector in Sentinel v2.3. Integrate Intune/Jamf exports manually or via custom script.

### ZT-03 — Network / Environment

**Principle:** Micro-segment; deny by default; inspect traffic.

| Control area | NIST 800-171 | Evidence |
|--------------|--------------|----------|
| Boundary protection | 3.13.1, 3.13.5, 3.13.6 | `micro-segmentation-policy.md` |
| Encryption in transit | 3.13.8 | `config_drift` TLS audit |
| Flow visibility | 3.14.6 | `log_aggregator` VPC flow coverage |

**Gaps:** ZTNA rollout; full flow documentation.

**Collector:** `zt_continuous_verification` aggregates network pillar signals.

### ZT-04 — Application and Workload

**Principle:** Secure workloads; validate configuration and changes.

| Control area | NIST 800-171 | Evidence |
|--------------|--------------|----------|
| Baseline configuration | 3.4.1, 3.4.3 | `config_drift` |
| Application integrity | 3.13.2, 3.13.3 | IaC baselines (manual) |

**Gaps:** CAB ticket linkage to deployments not automated.

**Policy:** `change-management-policy-v2.4.md`

### ZT-05 — Data

**Principle:** Protect data at rest and in use; classify and limit flows.

| Control area | NIST 800-171 | Evidence |
|--------------|--------------|----------|
| Encryption at rest | 3.13.8, 3.13.16 | `encryption_status` |
| Data lifecycle | 3.8.3, 3.8.9 | `retention_check` |
| CUI flow | 3.1.3 | Manual DLP/flow maps |

**Seed maturity:** Advanced — strongest Sentinel automation pillar.

**Policy:** `data-classification-policy-v2.0.md`, `encryption-key-management-policy-v2.3.md`

### ZT-06 — Visibility and Analytics

**Principle:** Log everything; analyze for threats.

| Control area | NIST 800-171 | Evidence |
|--------------|--------------|----------|
| Audit logging | 3.3.1, 3.3.5 | `log_aggregator` |
| Continuous monitoring | 3.14.6, 3.14.7 | Log completeness + SIEM (manual) |
| Assessment visibility | 3.12.1 | `self_assessment_report` |

**Gaps:** SIEM use-case library; UEBA not deployed.

**Policy:** `system-monitoring-policy-v2.0.md`, `monitoring-alerting-policy.md`

### ZT-07 — Automation and Orchestration

**Principle:** Automate policy enforcement and evidence collection.

| Control area | Evidence |
|--------------|----------|
| Evidence pipeline | `sentinel run-all` monthly |
| POA&M feed | Notion integration (manual workflow) |
| Continuous verification | `zt_continuous_verification`, `continuous-verification-procedure.md` |

**Gaps:** SOAR auto-remediation on roadmap.

---

## Maturity model

| Level | Characteristics |
|-------|-----------------|
| **Basic** | Siloed controls; periodic manual reviews |
| **Intermediate** | Integrated IAM/MFA/logging; monthly automation |
| **Advanced** | Continuous verification; micro-segmentation; threat hunting; ZTNA |

Target for CUI environments: **Advanced** on ZT-01, ZT-03, ZT-05, ZT-06 minimum.

---

## Continuous verification integration

Zero Trust requires ongoing validation—not annual checkbox compliance.

**Monthly procedure:** `policies/continuous-verification-procedure.md`

```bash
sentinel run zt_continuous_verification --provider aws
sentinel report --input data/zero-trust-pillars.csv --mode zt
```

---

## DFARS and incident response

Zero Trust visibility (ZT-06) supports DFARS incident detection—but **does not replace** IR procedures:

- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `policies/incident-response-policy.md`

---

## Notion tracking

Import `data/zero-trust-pillars.csv` and create **ZT Maturity** board view (see `docs/NOTION_SETUP.md`).

---

## Honest limitations

| In scope (v2.3) | Out of scope |
|-----------------|--------------|
| Pillar maturity CSV + ZT report mode | ZT product certification |
| `zt_continuous_verification` collector | Real-time policy engine |
| Policy and segmentation templates | Full device trust platform |
| Monthly evidence automation | Identity-aware proxy deployment |

---

## Related documents

- `policies/continuous-verification-procedure.md`
- `policies/micro-segmentation-policy.md`
- `docs/MITRE_ATTCK_COVERAGE.md`
- `docs/CMMC_L3_OVERVIEW.md`
- `data/zero-trust-pillars.csv`

---

*Framework version 2.3 — SOC2 Sentinel Toolkit.*