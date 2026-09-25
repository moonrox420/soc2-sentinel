# SOC2 Sentinel v2.5.0 — Comprehensive Operations & Directions Guide

**SOC2-Sentinel** is an enterprise continuous compliance automation platform designed for SOC 2 Type II, NIST SP 800-171/172, CMMC 2.0 Level 2, and CISA Zero Trust compliance architectures.

---

## Table of Contents

1. [Quick Start Methods](#1-quick-start-methods)
2. [CLI Command Reference](#2-cli-command-reference)
   - [Core Compliance & Scoring](#core-compliance--scoring)
   - [Merkle Evidence Vault](#merkle-evidence-vault)
   - [Vendor Risk Management (CC9.2)](#vendor-risk-management-cc92)
   - [User Access Reviews (CC6.1–CC6.3)](#user-access-reviews-cc61cc63)
   - [Multi-Channel Notifications](#multi-channel-notifications)
   - [Auditor Rooms & Evidence Export](#auditor-rooms--evidence-export)
   - [Dogfooding Self-Attestation Engine](#dogfooding-self-attestation-engine)
   - [Public & Auditor Trust Center](#public--auditor-trust-center)
   - [SIEM Event Streaming & Forwarding](#siem-event-streaming--forwarding)
3. [Embedded Web Dashboard & REST API](#3-embedded-web-dashboard--rest-api)
4. [Cloud Provider Authentication & Permissions](#4-cloud-provider-authentication--permissions)
5. [Quality Assurance & Verification Suite](#5-quality-assurance--verification-suite)

---

## 1. Quick Start Methods

### Method A: Standalone Windows Binary (Zero-Python)

1. Extract the release ZIP archive `dist/SOC2-Sentinel-Toolkit-v2.5.0-Windows.zip`.
2. Launch the interactive menu or run directly:
```powershell
# Validate cloud credentials
.\bin\sentinel.exe validate --provider aws

# Launch real-time web dashboard & daemon
.\bin\sentinel.exe serve --port 8443
```

### Method B: Python Development Virtual Environment

```powershell
# Initialize environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package
pip install -r requirements.txt
pip install -e .

# Run dashboard
sentinel serve
```

---

## 2. CLI Command Reference

### Core Compliance & Scoring

```powershell
# Launch web dashboard and daemon
sentinel serve [--port 8443] [--host 127.0.0.1]

# Run automated evidence collection across all 7 collectors
sentinel run-all --provider [aws|gcp|azure] [--tenant-id default]

# Compute multi-framework compliance posture (SOC 2, NIST, CMMC, Zero Trust)
sentinel scorecard [--evidence-dir evidence/] [--json]

# Detect configuration and access drift between successive collection runs
sentinel drift [--baseline evidence/] [--current evidence/]

# Check cloud account permissions and generate minimal IAM policies
sentinel onboarding --provider [aws|gcp|azure]

# Cryptographically verify evidence SHA-256 manifests and HMAC signatures
sentinel verify [evidence/2026-09-25]

# Generate 1-click executive HTML report and signed audit pack ZIP
sentinel audit-pack [evidence/2026-09-25] [--output-dir ./audit_packs]
```

### Merkle Evidence Vault

```powershell
# Seal evidence files into append-only cryptographic Merkle vault
sentinel vault seal --date 2026-09-25 [--tenant-id default]

# Verify cryptographic continuity of the ledger and evidence hashes
sentinel vault verify
```

### Vendor Risk Management (CC9.2)

```powershell
# Register a third-party vendor with risk tiering and compliance metadata
sentinel vendor-risk add --vendor-id "v-aws" --name "AWS" --tier 1 --status ACTIVE

# List all registered vendors
sentinel vendor-risk list

# Generate CC9.2 third-party risk report
sentinel vendor-risk report
```

### User Access Reviews (CC6.1–CC6.3)

```powershell
# Create a new quarterly entitlement access review campaign
sentinel access-review start --id "uar-2026-q3" --title "Q3 2026 Admin Privilege Review" --period "2026-Q3" --due-date "2026-10-31"

# List active campaigns
sentinel access-review list

# Record reviewer decision on an entitlement
sentinel access-review decide --id "uar-2026-q3" --item-id "item-001" --decision MAINTAIN --notes "Approved"

# Close and finalize an access review campaign with tamper-evident sign-off
sentinel access-review signoff --id "uar-2026-q3" --signer "CISO" --secret "secure-sign-key"
```

### Multi-Channel Notifications

```powershell
# Dispatch compliance notification alert
sentinel notify --channel generic --webhook-url "https://hooks.slack.com/services/..." --title "Compliance Alert" --message "Verification check complete"
```

### Auditor Rooms & Evidence Export

```powershell
# Create a time-bounded auditor room (e.g. 30 days)
sentinel audit-room create --id "room_2026" --title "FY26 SOC 2 Audit" --email "lead@assessor.com" --days 30

# List active audit rooms
sentinel audit-room list

# Generate 1-click complete auditor evidence ZIP package
sentinel audit-room export --id "room_2026"
```

### Dogfooding Self-Attestation Engine

```powershell
# Run continuous self-attestation against SOC2-Sentinel's codebase and architecture
sentinel dogfood
```

### Public & Auditor Trust Center

```powershell
# View trust center profile summary
sentinel trust-center view

# Generate standalone self-contained Trust Center HTML file
sentinel trust-center export-html --output ./trust_center.html
```

### SIEM Event Streaming & Forwarding

```powershell
# Export audit logs to NDJSON
sentinel siem export --format ECS --output ./siem_logs.ndjson

# Forward logs to SIEM endpoint
sentinel siem forward --target SPLUNK_HEC --endpoint "https://splunk.corp:8088/services/collector" --token "$SPLUNK_HEC_TOKEN"
```

---

## 3. Embedded Web Dashboard & REST API

Launch the dashboard with `sentinel serve`. Key endpoints:

| Endpoint | Method | Purpose |
|:---|:---:|:---|
| `/` | `GET` | Main executive dashboard & live console |
| `/trust-center` | `GET` | Public / Auditor Trust Center HTML view |
| `/api/scorecard` | `GET` | Real-time multi-framework compliance posture |
| `/api/drift` | `GET` | Baseline configuration & access drift detection |
| `/api/audit-rooms` | `GET, POST` | Manage auditor rooms and time-bounded access |
| `/api/dogfood` | `GET` | Self-attestation scoring & evidence evaluation |
| `/api/trust-center` | `GET` | Live Trust Center JSON metadata & profile |
| `/api/siem/export` | `POST` | Export security audit logs formatted for SIEMs |

---

## 4. Cloud Provider Authentication & Permissions

- **AWS**: Standard `~/.aws/credentials` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. See [docs/AWS_IAM_POLICY.json](docs/AWS_IAM_POLICY.json) for read-only least-privilege IAM policy.
- **GCP**: Application Default Credentials (`gcloud auth application-default login`) or `GOOGLE_APPLICATION_CREDENTIALS`. See [docs/GCP_SETUP.md](docs/GCP_SETUP.md).
- **Azure**: Azure CLI (`az login`) or `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`. See [docs/AZURE_SETUP.md](docs/AZURE_SETUP.md).

---

## 5. Quality Assurance & Verification Suite

```powershell
# Static type analysis (Mypy)
mypy sentinel --ignore-missing-imports

# Linting and style (Ruff)
ruff check sentinel

# Security AST scanner (Bandit)
bandit -r sentinel -ll
```
