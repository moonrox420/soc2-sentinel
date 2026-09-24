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
# Run instantaneous offline demo across all 7 collectors
.\bin\sentinel.exe run-all --provider mock

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
sentinel run-all --provider [mock|aws|gcp|azure] [--tenant-id default]

# Compute multi-framework compliance posture (SOC 2, NIST, CMMC, Zero Trust)
sentinel scorecard [--evidence-dir evidence/] [--json]

# Detect configuration and access drift between successive collection runs
sentinel drift [--baseline evidence/] [--current evidence/]

# Check cloud account permissions and generate minimal IAM policies
sentinel onboarding --provider [aws|gcp|azure]

# Cryptographically verify evidence SHA-256 manifests and HMAC signatures
sentinel verify [evidence/]

# Generate 1-click executive HTML report and signed audit pack ZIP
sentinel audit-pack [evidence/] [--output-dir ./audit_packs]
```

### Merkle Evidence Vault

```powershell
# Ingest evidence files into append-only cryptographic Merkle vault
sentinel vault ingest evidence/ [--tenant-id default]

# Generate and verify cryptographic inclusion proofs against Merkle root
sentinel vault verify [--evidence-id <hash>]

# Inspect vault status, total leaves, and current root hash
sentinel vault status
```

### Vendor Risk Management (CC9.2)

```powershell
# Register a third-party vendor with risk tiering and compliance metadata
sentinel vendor-risk add --name "AWS" --tier 1 --soc2-status "Valid" --soc2-expiry "2027-12-31" --notes "Primary cloud IaaS"

# List all registered vendors
sentinel vendor-risk list

# Scan for upcoming vendor compliance expirations
sentinel vendor-risk check-expirations --within-days 90

# Calculate vendor risk assessment score
sentinel vendor-risk assess --name "AWS"
```

### User Access Reviews (CC6.1–CC6.3)

```powershell
# Create a new quarterly entitlement access review campaign
sentinel access-review create --title "Q3 2026 Admin Privilege Review" --deadline "2026-10-31"

# List active campaigns
sentinel access-review list

# Record reviewer approval / revocation on an entitlement
sentinel access-review review --campaign-id "<id>" --user "alice@example.com" --action approve --reviewer "ciso@company.com"

# Close and finalize an access review campaign with tamper-evident sign-off
sentinel access-review finalize --campaign-id "<id>"
```

### Multi-Channel Notifications

```powershell
# Send test notification to configured Slack/Teams/PagerDuty channels
sentinel notify test --channel slack

# Dispatch high-severity compliance alert
sentinel notify send --severity critical --title "Open SSH Port Detected" --message "Port 22 open on 0.0.0.0/0 in prod VPC"
```

### Auditor Rooms & Evidence Export

```powershell
# Create a time-bounded auditor room (e.g. 30 days)
sentinel audit-room create --name "FY26 SOC 2 Audit" --auditor "Assessor Corp" --email "lead@assessor.com" --days 30

# List active audit rooms
sentinel audit-room list

# Generate 1-click complete auditor evidence ZIP package
sentinel audit-room export-package --room-id "<id>" --output ./audit_package.zip
```

### Dogfooding Self-Attestation Engine

```powershell
# Run continuous self-attestation against SOC2-Sentinel's codebase and architecture
sentinel dogfood run [--json]
```

### Public & Auditor Trust Center

```powershell
# Generate standalone self-contained Trust Center HTML file
sentinel trust-center export --output ./trust_center.html
```

### SIEM Event Streaming & Forwarding

```powershell
# Export audit logs to NDJSON in Elastic Common Schema (ECS) format
sentinel siem export --format ecs --output ./siem_logs.ndjson

# Forward logs via RFC 5424 Syslog / Splunk HEC / Datadog
sentinel siem forward --target splunk --url "https://splunk.corp:8088" --token "$SPLUNK_HEC_TOKEN"
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
| `/api/dogfood` | `GET, POST` | Self-attestation scoring & evidence evaluation |
| `/api/trust-center` | `GET` | Live Trust Center JSON metadata & profile |
| `/api/siem/export` | `POST` | Export security audit logs formatted for SIEMs |
| `/api/siem/forward` | `POST` | Stream security logs to Splunk / Datadog / Webhook |

---

## 4. Cloud Provider Authentication & Permissions

- **AWS**: Standard `~/.aws/credentials` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. See [docs/AWS_IAM_POLICY.json](docs/AWS_IAM_POLICY.json) for read-only least-privilege IAM policy.
- **GCP**: Application Default Credentials (`gcloud auth application-default login`) or `GOOGLE_APPLICATION_CREDENTIALS`. See [docs/GCP_SETUP.md](docs/GCP_SETUP.md).
- **Azure**: Azure CLI (`az login`) or `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`. See [docs/AZURE_SETUP.md](docs/AZURE_SETUP.md).

---

## 5. Quality Assurance & Verification Suite

```powershell
# Run 239 unit & integration tests with coverage
pytest --cov=sentinel --cov-report=term-missing

# Static type analysis (Mypy)
mypy sentinel

# Linting and style (Ruff)
ruff check sentinel tests

# Security AST scanner (Bandit)
bandit -r sentinel -ll
```
