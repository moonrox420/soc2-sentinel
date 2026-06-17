# CMMC Level 2 Self-Assessment Guide

Use SOC2 Sentinel to produce a **good-faith self-assessment** of CMMC Level 2 practices aligned with NIST 800-171 Rev 2.

> **Disclaimer:** Self-assessment is not CMMC certification. SPRS scores and contract eligibility may require C3PAO assessment depending on your acquisition path. This guide does not guarantee any particular SPRS score or certification outcome.

## Who this is for

- Defense contractors handling FCI/CUI
- Regulated SaaS vendors preparing for customer security reviews
- Teams building evidence before engaging a C3PAO

## Prerequisites

1. Policies customized in `policies/`
2. Controls matrix generated: `python scripts/generate_controls_csv.py`
3. At least one cloud evidence run: `sentinel run-all --provider aws`

## Step 1 — Understand CMMC L2 scope

CMMC Level 2 encompasses **110 NIST 800-171 practices** (including enhanced requirements). This toolkit's `controls-matrix.csv` maps a **pragmatic subset** tied to SOC 2 TSC controls and Sentinel automation hooks—not every 110 practices individually.

Expand the CSV for full practice coverage before submitting SPRS scores.

## Step 2 — Collect automated evidence

```bash
sentinel run-all --provider aws
```

Review each `evidence/<date>/<control>/report.json`:

| Status | Meaning | Action |
|--------|---------|--------|
| `green` | Metrics within threshold | Link to control row as supporting evidence |
| `yellow` | Borderline / warning | Document compensating control or open POA&M |
| `red` | Failing threshold | Mark control **Not Met** or **POA&M** until remediated |

### Key metrics to record

| Collector | Metrics |
|-----------|---------|
| `iam_access_review` | `orphaned_accounts`, `privileged_count`, `days_since_last_review` |
| `log_aggregator` | `log_coverage_percent`, `max_gap_hours` |
| `config_drift` | `mfa_enforcement_percent`, `weak_tls_listeners` |
| `encryption_status` | `unencrypted_cui_count`, `keys_pending_rotation` |
| `retention_check` | `objects_past_retention` |

## Step 3 — Update controls matrix

Edit `data/controls-matrix.csv` column **CMMC L2 Status**:

| Value | When to use |
|-------|-------------|
| **Met** | Policy + procedure + evidence demonstrate practice |
| **Not Met** | Gap with no compensating control |
| **POA&M** | Gap with documented remediation plan and date |
| **Not Applicable** | Practice outside assessment boundary (document justification) |

Also update **Implementation Statement** with specifics—avoid boilerplate.

Example:

> "Quarterly IAM review completed 2026-05-15. Sentinel CC6.1 run shows 0 orphaned accounts, 2 privileged users with signed attestations on file."

## Step 4 — Generate report

```bash
sentinel report --input data/controls-matrix.csv --output-dir reports/
```

Outputs:

- `reports/self-assessment.json` — machine-readable scores
- `reports/self-assessment.md` — human-readable summary

### Interpreting scores

- **Family breakdown** — identifies weak 800-171 families (AC, SC, etc.)
- **overall_score_percent** — Met ÷ (total applicable controls)
- **poam_count** — controls deferred with plan

**Do not** submit SPRS scores based solely on this percentage without reviewing every applicable practice.

## Step 5 — Manual evidence checklist

Practices without Sentinel hooks still require documentation:

| Practice area | Example evidence |
|---------------|------------------|
| AT — Awareness | LMS completion export, phishing simulation results |
| PS — Personnel | Background check policy, termination checklist |
| PE — Physical | Office access logs or cloud provider SOC letter |
| IR — Incident Response | Tabletop report, `DFARS_7012_INCIDENT_PROCEDURE.md` |
| MA — Maintenance | Patch compliance report |

## Step 6 — SPRS submission (if applicable)

Organizations submitting NIST SP 800-171 DoD Assessment Methodology scores to SPRS must:

1. Complete the official **NIST 800-171A** assessment for each practice
2. Assign a confidence level per DoD guidance
3. Retain evidence for DIBCAC review

SOC2 Sentinel accelerates evidence gathering—it does not replace the official scoring worksheet.

## Step 7 — POA&M management

For each **POA&M** control:

- Owner and target date
- Link to Sentinel finding (`findings[].issue`)
- Retest command after fix: `sentinel run <collector> --provider aws`

Close POA&M only after green status or documented risk acceptance by executive management.

## Limitations (read honestly)

| Capability | Included | Not included |
|------------|----------|--------------|
| IAM/orphan account scan | Yes | Full Entra ID/GCP IAM on all providers |
| Logging coverage | Yes | SIEM alert tuning proof |
| Encryption at rest | Yes | FIPS certification attestation |
| CMMC certificate | No | C3PAO assessment |
| Legal compliance opinion | No | Consult counsel |

## Next steps

- **C3PAO path:** `docs/C3PAO_PREP_30_60_90.md`
- **NIST mapping:** `docs/NIST_800_171_CROSSWALK.md`
- **Executive briefing:** `docs/EXECUTIVE_SUMMARY_TEMPLATE.md`