# What's Inside — SOC2 Sentinel Toolkit v2.3.0

Complete inventory of deliverables. No filler modules, no placeholder PDFs, no fictional case studies.

> **Disclaimer:** This toolkit supports compliance readiness. It does not constitute legal advice or guarantee certification.

---

## Core software

| Component | Path | Description |
|-----------|------|-------------|
| CLI entrypoint | `sentinel/cli.py` | `run`, `run-all`, `report` (--mode cmmc \| zt) |
| IAM access review | `sentinel/collectors/iam_access_review.py` | CC6.1 — users, orphans, privilege |
| Log aggregator | `sentinel/collectors/log_aggregator.py` | CC7.1 — trail/sink coverage |
| Config drift | `sentinel/collectors/config_drift.py` | CC6.2 — MFA, TLS, HTTP exposure |
| Encryption status | `sentinel/collectors/encryption_status.py` | C1.2 — at-rest encryption, KMS |
| Retention check | `sentinel/collectors/retention_check.py` | C1.4 — lifecycle compliance |
| Resilience testing | `sentinel/collectors/resilience_testing.py` | A1.2 — backup/resilience signals |
| ZT continuous verification | `sentinel/collectors/zt_continuous_verification.py` | ZT-1 — cross-pillar verification |
| Self-assessment | `sentinel/collectors/self_assessment_report.py` | CMMC + ZT score from CSV |
| AWS provider | `sentinel/providers/aws.py` | Full boto3 integration |
| GCP provider | `sentinel/providers/gcp.py` | GCS + Cloud Logging |
| Azure provider | `sentinel/providers/azure.py` | Storage management APIs |
| Mock provider | `sentinel/providers/mock.py` | Offline demo data |
| Evidence schema | `data/evidence-schema.json` | JSON Schema validation |
| CMMC L2 generator | `scripts/generate_cmmc_l2_110.py` | 110-practice CSV |
| Controls generator | `scripts/generate_controls_csv.py` | Notion-ready CSV export |
| Test suite | `tests/` | Pytest fixtures and collector tests |

### Install

```bash
pip install -e .
sentinel run-all --provider mock
sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc
```

---

## Policies (17 files)

### Core library

| File | Version | Focus |
|------|---------|-------|
| `access-control-policy-v2.3.md` | 2.3 | Logical access, JML, quarterly review |
| `authentication-access-policy-v2.1.md` | 2.1 | SSO, MFA, service accounts |
| `privileged-access-policy-v2.2.md` | 2.2 | JIT, break-glass, PAM |
| `system-monitoring-policy-v2.0.md` | 2.0 | Centralized logging, coverage |
| `monitoring-alerting-policy.md` | 1.0 | Alert tiers, escalation |
| `change-management-policy-v2.4.md` | 2.4 | CAB, emergency changes, drift |
| `risk-management-policy-v2.1.md` | 2.1 | Risk register, POA&M linkage |
| `backup-recovery-policy-v2.2.md` | 2.2 | RPO/RTO, restore testing |
| `business-continuity-policy.md` | 1.0 | BIA, tabletop exercises |
| `data-classification-policy-v2.0.md` | 2.0 | Tiers, CUI handling |
| `encryption-key-management-policy-v2.3.md` | 2.3 | Algorithms, rotation, KMS |
| `secure-transmission-policy-v2.1.md` | 2.1 | TLS, VPN, API security |
| `data-retention-disposal-policy-v2.2.md` | 2.2 | Lifecycle, secure disposal |

### v2.3 additions

| File | Version | Focus |
|------|---------|-------|
| `incident-response-policy.md` | 1.0 | IR program; DFARS links |
| `micro-segmentation-policy.md` | 1.0 | Deny-by-default, ZT network |
| `continuous-verification-procedure.md` | 1.0 | Monthly ZT verification |
| `supply-chain-risk-management-policy.md` | 1.0 | Vendor risk, 3.12.4 |

Each policy includes: Purpose, Scope, Roles, numbered Procedures, Sentinel evidence hooks, review cadence, CUI/defense notes.

---

## Documentation (20+ files)

### Setup

| File | Purpose |
|------|---------|
| `docs/SETUP.md` | Install, quick start, troubleshooting |
| `docs/NOTION_SETUP.md` | 7 databases, ATT&CK + ZT views |
| `docs/GCP_SETUP.md` | APIs, service accounts |
| `docs/AZURE_SETUP.md` | DefaultAzureCredential |
| `docs/AWS_IAM_POLICY.json` | Read-only IAM policy |

### Compliance playbooks

| File | Purpose |
|------|---------|
| `docs/MASTER_REFERENCE_v2.3.md` | Complete toolkit index |
| `docs/NIST_800_171_CROSSWALK.md` | 14 control families |
| `docs/NIST_800_172_CROSSWALK.md` | Enhanced controls (L3) |
| `docs/CMMC_L2_CONTROLS_REFERENCE.md` | 110 practice summary |
| `docs/CMMC_L2_SELF_ASSESSMENT.md` | Self-assessment workflow |
| `docs/CMMC_L3_OVERVIEW.md` | L3 preparation guide |
| `docs/C3PAO_PREP_30_60_90.md` | Certification prep timeline |
| `docs/DFARS_7012_INCIDENT_PROCEDURE.md` | 72h workflow, classification, DIBNet, mermaid tree |
| `docs/MITRE_ATTCK_COVERAGE.md` | ATT&CK technique mapping |
| `docs/ZERO_TRUST_FRAMEWORK.md` | Seven pillar maturity |
| `docs/EXECUTIVE_SUMMARY_TEMPLATE.md` | Leadership briefing (CMMC X/110, ATT&CK, ZT) |

### Operational templates (`docs/templates/`)

| File | Purpose |
|------|---------|
| `dibnet-report-template.md` | Redacted DIBNet submission fields |
| `tabletop-test-record.md` | Annual DFARS tabletop |
| `threat-hunting-playbook.md` | Hunt queries for log/IAM exports |
| `vendor-security-questionnaire.md` | Vendor assessment |

---

## Data files

| File | Purpose |
|------|---------|
| `data/cmmc-l2-controls-110.csv` | 110 CMMC L2 practices |
| `data/l3-enhanced-controls.csv` | 800-172 enhanced seed |
| `data/attck-mapping.csv` | ATT&CK mapping |
| `data/zero-trust-pillars.csv` | ZT pillar maturity |
| `data/controls-matrix.csv` | SOC2 TSC matrix |

### Notion imports (`data/notion-import/`)

| File | Database |
|------|----------|
| `soc2-controls.csv` | Controls Matrix |
| `cmmc-l2-controls.csv` | CMMC L2 Controls |
| `poam-tracker-seed.csv` | POA&M |
| `incident-reporting-tracker-seed.csv` | Incident Reporting |
| `pre-assessment-readiness.csv` | Pre-Assessment Gates |
| `vendor-assessment-seed.csv` | Vendor Assessment |

---

## Sales / marketing assets (this folder)

| File | Use |
|------|-----|
| `sales/gumroad-description.md` | Product listing copy |
| `sales/carrd-landing-copy.md` | Landing page sections |
| `sales/whats-inside.md` | This inventory |

---

## Evidence output structure

After `sentinel run-all`:

```
evidence/
  2026-06-17/
    CC6.1/
      report.json
      iam_users_export.csv
    CC7.1/
      report.json
    CC6.2/
      report.json
    C1.2/
      report.json
    C1.4/
      report.json
    A1.2/
      report.json
    ZT-1/
      report.json
```

Status values: `green`, `yellow`, `red` — computed per control thresholds.

---

## Framework coverage (honest)

| Framework | What toolkit covers | What you still need |
|-----------|--------------------|---------------------|
| SOC 2 | Security/Confidentiality/Availability evidence for mapped TSC | Auditor engagement, Type II period |
| NIST 800-171 | Crosswalk for 14 families; automation for subset | SSP, manual AT/PS/PE/MA evidence |
| CMMC L2 | 110-practice CSV + self-assessment CLI | C3PAO assessment for certification |
| CMMC L3 | 800-172 crosswalk, ZT, ATT&CK, hunting playbook | Enhanced controls, UEBA, MDM |
| DFARS 7012 | IR policy, expanded procedure, DIBNet template, tabletop | Legal, FSO, live DIBNet submission |
| Zero Trust | Pillar CSV, continuous verification collector | ZTNA, device trust platform |
| MITRE ATT&CK | Mapping + hunt playbook | EDR, SIEM detection rules |

**Seed honesty:** Default CMMC CSV ships with 22/110 practices marked Met via automation. Your score depends on implementation.

---

## Dependencies

- `boto3`, `jsonschema`
- `google-cloud-*` (GCP)
- `azure-identity`, `azure-mgmt-*` (Azure)
- Python ≥3.10

---

## License

MIT — see `LICENSE`

---

## Version

**2.3.0** — DFARS-tested workflows, CMMC 110 practices, ATT&CK mapping, Zero Trust maturity, 7 collectors, 17 policies, 4 operational templates.