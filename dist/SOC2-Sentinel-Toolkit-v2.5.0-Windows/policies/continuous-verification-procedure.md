# Continuous Verification Procedure

**Version:** 1.0  
**Owner:** Security Engineering  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This procedure implements Zero Trust **never trust, always verify** principles using SOC2 Sentinel automation. Continuous verification reduces—but does not eliminate—risk. It is not a substitute for periodic access certification, C3PAO assessment, or real-time threat detection. Not legal advice.

## Purpose

Define how [ORGANIZATION_NAME] continuously validates identity, device, network, and data security posture between formal quarterly assessments—supporting NIST 800-171 CA/AC families, CMMC L2/L3, and Zero Trust maturity targets.

## Scope

Cloud IAM, logging pipelines, encryption configuration, MFA enforcement, resilience controls, and Zero Trust pillar evidence across AWS, GCP, Azure, and integrated SaaS where collectors apply.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security Engineering** | Schedules and reviews automated verification runs |
| **Platform Engineering** | Remediates findings within SLA |
| **Compliance Lead** | Updates Notion/matrix status from evidence bundles |
| **Security Operations** | Escalates red findings; correlates with SIEM |
| **Management** | Reviews monthly verification summary |

## Verification schedule

| Activity | Frequency | Tool / collector | Output |
|----------|-----------|------------------|--------|
| Full evidence sweep | Monthly | `sentinel run-all` | `evidence/[DATE]/` |
| IAM access posture | Monthly | `iam_access_review` | CC6.1 bundle |
| Log completeness | Monthly | `log_aggregator` | CC7.1 bundle |
| MFA / TLS / exposure drift | Monthly | `config_drift` | CC6.2 bundle |
| Encryption at rest | Monthly | `encryption_status` | C1.2 bundle |
| Retention / lifecycle | Monthly | `retention_check` | C1.4 bundle |
| Backup / resilience signals | Monthly | `resilience_testing` | A1.2 bundle |
| Zero Trust pillar roll-up | Monthly | `zt_continuous_verification` | ZT-1 bundle |
| CMMC L2 score | Monthly or pre-audit | `sentinel report --mode cmmc` | Self-assessment report |
| ZT maturity score | Quarterly | `sentinel report --mode zt` | ZT maturity report |

## Procedure steps

### Step 1 — Execute collectors

```powershell
cd C:\Users\droxa\soc2-sentinel
.\.venv\Scripts\Activate.ps1
sentinel run-all --provider aws --output-base .
```

For demo or CI validation without credentials:

```bash
sentinel run-all --provider mock
```

### Step 2 — Validate evidence schema

Confirm each `report.json` conforms to `data/evidence-schema.json`. Reject incomplete runs from compliance dashboards.

### Step 3 — Triage findings

| Status | Action | SLA |
|--------|--------|-----|
| **Green** | Log in Evidence Log; no POA&M | — |
| **Yellow** | Create POA&M; remediate within 30 days | 30 days |
| **Red** | Page on-call if production CUI scope; remediate within 7 days | 7 days |

Critical red classes (immediate escalation):

- Logging disabled on CUI-scoped resources
- Unencrypted confidential/CUI stores
- Privileged accounts without MFA
- Open admin ports on production workloads

### Step 4 — Update tracking systems

1. Import status to Notion **Controls Matrix** and **Evidence Log** (see `docs/NOTION_SETUP.md`)
2. Link `report.json` paths to control rows
3. Open POA&M items for yellow/red findings with NIST 800-171 mapping from `data/cmmc-l2-controls-110.csv`

### Step 5 — Generate roll-up reports

```bash
sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc
sentinel report --input data/zero-trust-pillars.csv --mode zt
```

Distribute summary to leadership using `docs/EXECUTIVE_SUMMARY_TEMPLATE.md`.

### Step 6 — Attest and archive

Store evidence in immutable storage (S3 Object Lock, Azure immutable blob, etc.) for assessment periods. Notion displays status only—formal evidence lives in `evidence/` and WORM storage.

## Zero Trust continuous verification

The `zt_continuous_verification` collector aggregates signals across pillars defined in `data/zero-trust-pillars.csv`:

| Pillar | Primary collectors |
|--------|-------------------|
| ZT-01 User | `iam_access_review`, `config_drift` |
| ZT-03 Network | `config_drift`, `log_aggregator` |
| ZT-05 Data | `encryption_status`, `retention_check` |
| ZT-06 Visibility | `log_aggregator`, `self_assessment_report` |

See `docs/ZERO_TRUST_FRAMEWORK.md` for maturity targets and gaps.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Control mapping |
|-----------|-----------------|
| `zt_continuous_verification` | ZT-1 — cross-pillar verification |
| `iam_access_review` | CC6.1, 3.1.1, 3.1.5 |
| `log_aggregator` | CC7.1, 3.3.1 |
| `config_drift` | CC6.2, 3.4.2 |
| `encryption_status` | C1.2, 3.13.8 |
| `retention_check` | C1.4, 3.8.3 |
| `resilience_testing` | A1.2, 3.8.9 |

## Honest limitations

| In scope | Out of scope |
|----------|--------------|
| Monthly configuration and evidence verification | Real-time session re-authentication |
| POA&M feed from automated findings | Device health (MDM) — manual in v2.3 |
| ZT maturity scoring from CSV + collectors | UEBA / behavioral analytics |
| Repeatable audit artifacts | C3PAO certification |

Continuous verification **supplements**—not replaces—quarterly access reviews, annual risk assessments, and incident response capability.

## Review Cadence

- **Procedure review:** Annually  
- **Collector threshold tuning:** Quarterly  
- **Executive summary:** Monthly

## Related Documents

- `docs/ZERO_TRUST_FRAMEWORK.md`
- `docs/CMMC_L2_CONTROLS_REFERENCE.md`
- `policies/access-control-policy-v2.3.md`
- `policies/micro-segmentation-policy.md`
- `policies/monitoring-alerting-policy.md`
- `docs/NOTION_SETUP.md`