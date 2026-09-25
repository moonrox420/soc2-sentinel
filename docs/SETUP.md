# SOC2 Sentinel — Setup Guide

**Version:** 2.5.0  
**Last updated:** September 2026

> **Disclaimer:** SOC2 Sentinel automates evidence collection to support compliance readiness. It does not provide legal advice, perform audits, or guarantee SOC 2, CMMC, or NIST 800-171 certification.

## Prerequisites

- **Python 3.10+**
- **Git** (optional, for cloning)
- **Cloud credentials** for your target provider (`aws`, `gcp`, or `azure`)

## Installation

### 1. Obtain the toolkit

```bash
cd soc2-sentinel
```

Or clone/unzip the distribution to your preferred directory.

### 2. Create a virtual environment (recommended)

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Verify CLI

```bash
sentinel --help
```

## Quick start (live validation)

Validate your configured cloud provider credentials:

```bash
sentinel validate --provider aws
```

Run all automated evidence collectors:

```bash
sentinel run-all --provider aws
```

Output maps collector names to evidence file paths:

```json
{
  "iam_access_review": "evidence/2026-09-25/CC6.1/report.json",
  "log_aggregator": "evidence/2026-09-25/CC7.1/report.json",
  "config_drift": "evidence/2026-09-25/CC6.2/report.json",
  "encryption_status": "evidence/2026-09-25/C1.2/report.json",
  "retention_check": "evidence/2026-09-25/C1.4/report.json",
  "resilience_testing": "evidence/2026-09-25/A1.2/report.json",
  "zt_continuous_verification": "evidence/2026-09-25/ZT-1/report.json"
}
```

Evidence is written under `evidence/<YYYY-MM-DD>/<CONTROL_ID>/` with `report.json`, `manifest.json`, and supporting artifacts.

## Running individual collectors

```bash
sentinel run iam_access_review --provider aws
sentinel run log_aggregator --provider aws
sentinel run config_drift --provider gcp --control-id CC6.2
sentinel run encryption_status --provider azure
sentinel run retention_check --provider aws
```

Override output directory:

```bash
sentinel run-all --provider aws --output-base C:\compliance\evidence
```

## Collector → control mapping

| Collector | Default Control ID | Policy alignment |
|-----------|-------------------|------------------|
| `iam_access_review` | CC6.1 | Access Control, Privileged Access |
| `log_aggregator` | CC7.1 | System Monitoring |
| `config_drift` | CC6.2 | Authentication, Change Management |
| `encryption_status` | C1.2 | Encryption, Data Classification |
| `retention_check` | C1.4 | Data Retention & Disposal |
| `resilience_testing` | A1.2 | Backup & Business Continuity |
| `zt_continuous_verification` | ZT-1 | Zero Trust Architecture |

## Generate controls data

```bash
python scripts/generate_controls_csv.py
```

Produces `data/controls-matrix.csv` for Notion import and self-assessment.

## CMMC self-assessment report

After updating control statuses in the CSV:

```bash
sentinel report --input data/controls-matrix.csv --output-dir reports/
```

## Cloud provider setup

- **AWS:** `docs/AWS_IAM_POLICY.json` + standard credential chain (`AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, or IAM role)
- **GCP:** `docs/GCP_SETUP.md`
- **Azure:** `docs/AZURE_SETUP.md`

## Evidence schema

All `report.json` files validate against `data/evidence-schema.json` fields:

- `control_id`, `collection_timestamp`, `status` (green/yellow/red)
- `metrics`, `evidence_artifacts`, `findings`, `notes`, `provider`

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| `sentinel: command not found` | Re-activate venv; confirm `pip install -e .` completed |
| AWS `NoCredentialsError` | Configure AWS_PROFILE or environment credentials |
| GCP `GOOGLE_CLOUD_PROJECT` missing | Set env var per GCP_SETUP.md |
| Azure `AZURE_SUBSCRIPTION_ID` missing | Set env var per AZURE_SETUP.md |
| Schema validation error | Upgrade toolkit; check collector output format |

## Next steps

1. Customize policies in `policies/` with `[ORGANIZATION_NAME]`
2. Import controls to Notion — `docs/NOTION_SETUP.md`
3. Schedule monthly `sentinel run-all` in CI or cron
4. Map NIST families — `docs/NIST_800_171_CROSSWALK.md`

## Support expectations

This toolkit is designed for **defense contractors and regulated SaaS** teams building evidence pipelines. Automated output supplements—not replaces—auditor judgment, penetration testing, and formal assessment by a C3PAO where CMMC certification is required.