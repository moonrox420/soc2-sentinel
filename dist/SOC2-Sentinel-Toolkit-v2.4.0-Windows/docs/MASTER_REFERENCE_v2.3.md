# SOC2 Sentinel Toolkit — Master Reference v2.3

Complete index of the toolkit. Use this page as the navigation hub for policies, docs, data, collectors, and sales assets.

> **Disclaimer:** SOC2 Sentinel provides policy templates, operational procedures, and evidence automation. It is **not legal advice** and does **not** guarantee SOC 2, CMMC, NIST 800-171/172, or DFARS compliance outcomes. No fictional customer case studies are included. Buyers must customize templates and engage qualified assessors.

**Version:** 2.3.0  
**Python:** ≥3.10  
**License:** MIT

---

## Quick start

```powershell
cd C:\Users\droxa\soc2-sentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
sentinel run-all --provider mock
sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc
```

Evidence output: `evidence/<YYYY-MM-DD>/<control_id>/report.json`

---

## CLI commands

| Command | Description |
|---------|-------------|
| `sentinel run <collector> --provider <aws\|gcp\|azure\|mock>` | Single collector |
| `sentinel run-all --provider <provider>` | All 7 collectors |
| `sentinel report --input <csv> --mode cmmc` | CMMC L2 self-assessment |
| `sentinel report --input <csv> --mode zt` | Zero Trust maturity report |

---

## Collectors (7)

| Collector | Control ID | ATT&CK / ZT | Purpose |
|-----------|------------|-------------|---------|
| `iam_access_review` | CC6.1 | T1078 | IAM users, orphans, privilege |
| `log_aggregator` | CC7.1 | T1087, T1567 | Audit log coverage |
| `config_drift` | CC6.2 | T1562.001, T1556 | MFA, TLS, exposure drift |
| `encryption_status` | C1.2 | T1530 | Encryption at rest |
| `retention_check` | C1.4 | T1485 | Lifecycle compliance |
| `resilience_testing` | A1.2 | T1486 | Backup/resilience signals |
| `zt_continuous_verification` | ZT-1 | ZT pillars | Cross-pillar verification |

Schema: `data/evidence-schema.json`

---

## Policies (17)

### Core (v1.x – v2.4)

| File | Version | Focus |
|------|---------|-------|
| `access-control-policy-v2.3.md` | 2.3 | Logical access, JML |
| `authentication-access-policy-v2.1.md` | 2.1 | SSO, MFA |
| `privileged-access-policy-v2.2.md` | 2.2 | JIT, break-glass |
| `system-monitoring-policy-v2.0.md` | 2.0 | Centralized logging |
| `monitoring-alerting-policy.md` | 1.0 | Alert tiers |
| `change-management-policy-v2.4.md` | 2.4 | CAB, emergency changes |
| `risk-management-policy-v2.1.md` | 2.1 | Risk register, POA&M |
| `backup-recovery-policy-v2.2.md` | 2.2 | RPO/RTO |
| `business-continuity-policy.md` | 1.0 | BIA, tabletop |
| `data-classification-policy-v2.0.md` | 2.0 | Tiers, CUI |
| `encryption-key-management-policy-v2.3.md` | 2.3 | KMS, algorithms |
| `secure-transmission-policy-v2.1.md` | 2.1 | TLS, VPN |
| `data-retention-disposal-policy-v2.2.md` | 2.2 | Lifecycle |

### v2.3 additions

| File | Version | Focus |
|------|---------|-------|
| `incident-response-policy.md` | 1.0 | IR program; links DFARS procedure |
| `micro-segmentation-policy.md` | 1.0 | Deny-by-default, ZT network |
| `continuous-verification-procedure.md` | 1.0 | Monthly ZT verification |
| `supply-chain-risk-management-policy.md` | 1.0 | Vendor risk, 3.12.4 |

---

## Documentation

### Setup and operations

| File | Purpose |
|------|---------|
| `docs/SETUP.md` | Install, troubleshooting |
| `docs/NOTION_SETUP.md` | Workspace databases and views |
| `docs/GCP_SETUP.md` | GCP credentials |
| `docs/AZURE_SETUP.md` | Azure credentials |
| `docs/AWS_IAM_POLICY.json` | Read-only IAM policy |

### Compliance playbooks

| File | Purpose |
|------|---------|
| `docs/NIST_800_171_CROSSWALK.md` | 14 family crosswalk |
| `docs/NIST_800_172_CROSSWALK.md` | Enhanced controls (L3) |
| `docs/CMMC_L2_CONTROLS_REFERENCE.md` | 110 practice summary |
| `docs/CMMC_L2_SELF_ASSESSMENT.md` | Self-assessment workflow |
| `docs/CMMC_L3_OVERVIEW.md` | L3 preparation |
| `docs/C3PAO_PREP_30_60_90.md` | 30/60/90 prep timeline |
| `docs/DFARS_7012_INCIDENT_PROCEDURE.md` | 72h IR, classification, DIBNet |
| `docs/MITRE_ATTCK_COVERAGE.md` | ATT&CK technique map |
| `docs/ZERO_TRUST_FRAMEWORK.md` | Seven pillar maturity |
| `docs/EXECUTIVE_SUMMARY_TEMPLATE.md` | Leadership briefing |
| `docs/MASTER_REFERENCE_v2.3.md` | This index |

### Operational templates (`docs/templates/`)

| File | Purpose |
|------|---------|
| `dibnet-report-template.md` | Redacted DIBNet field template |
| `tabletop-test-record.md` | Annual DFARS tabletop |
| `threat-hunting-playbook.md` | Hunt queries for log/IAM exports |
| `vendor-security-questionnaire.md` | Vendor assessment |

---

## Data files

| File | Purpose |
|------|---------|
| `data/controls-matrix.csv` | SOC2 TSC control matrix |
| `data/cmmc-l2-controls-110.csv` | 110 CMMC L2 practices |
| `data/l3-enhanced-controls.csv` | 800-172 enhanced seed |
| `data/attck-mapping.csv` | ATT&CK technique mapping |
| `data/zero-trust-pillars.csv` | ZT pillar maturity |
| `data/evidence-schema.json` | JSON Schema for reports |

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

## Framework coverage (honest)

| Framework | Toolkit provides | You still need |
|-----------|------------------|----------------|
| **SOC 2** | Mapped TSC evidence for 7 automatable areas | Auditor, Type II period |
| **NIST 800-171** | Crosswalk + ~20% automated Met (seed) | SSP, manual AT/PS/PE/MA |
| **CMMC L2** | 110-control CSV + `sentinel report` | C3PAO for certification |
| **CMMC L3** | 800-172 crosswalk + ZT/ATT&CK docs | Enhanced controls, hunting program |
| **DFARS 7012** | IR policy, procedure, DIBNet template, tabletop | Legal, FSO, live DIBNet submission |
| **Zero Trust** | Pillar CSV + continuous verification | ZTNA, MDM, SIEM/UEBA |
| **MITRE ATT&CK** | Mapping + hunt playbook | EDR, SIEM detection rules |

---

## Cloud providers

| Provider | Command | Setup doc |
|----------|---------|-----------|
| Mock | `--provider mock` | None |
| AWS | `--provider aws` | `docs/AWS_IAM_POLICY.json` |
| GCP | `--provider gcp` | `docs/GCP_SETUP.md` |
| Azure | `--provider azure` | `docs/AZURE_SETUP.md` |

---

## Sales assets

| File | Use |
|------|-----|
| `sales/whats-inside.md` | Product inventory |
| `sales/gumroad-description.md` | Marketplace listing |
| `sales/carrd-landing-copy.md` | Landing page |

Suggested price (seller note): **$497** one-time — adjust for v2.3 scope.

---

## Tests

```powershell
pytest
```

Fixtures: `tests/fixtures/`

---

## Version history

| Version | Highlights |
|---------|------------|
| 1.6 | 5 collectors, 13 policies, basic CMMC |
| **2.3** | 7 collectors, 17 policies, 110 CMMC practices, DFARS expansion, ZT/ATT&CK/L3 docs, 4 operational templates, 5 new Notion DBs |

---

## Support and limitations

- Documentation-first product; no guaranteed SLA unless purchased separately
- Collectors run **locally**; evidence stays in your `evidence/` directory
- Does not file DIBNet reports, replace C3PAO, or provide legal advice
- Does not include fictional case studies or fabricated certification claims

---

*Master Reference v2.3 — SOC2 Sentinel Toolkit.*