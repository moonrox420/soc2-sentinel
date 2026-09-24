# SOC2 Sentinel Toolkit v2.5.0

**Enterprise-grade continuous compliance automation platform & audit accelerator.**

Built for **SOC 2 Type II**, **NIST SP 800-171 / 800-172**, **CMMC 2.0 Level 2**, **DFARS 7012**, **MITRE ATT&CK**, and **CISA Zero Trust** compliance workflows.

[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-239%20passed-success.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-81.45%25-brightgreen.svg)](pyproject.toml)
[![Security: Bandit](https://img.shields.io/badge/security-bandit%20clean-brightgreen.svg)](sentinel/)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checker-mypy%20clean-blue.svg)](pyproject.toml)

---

## 🌟 What's New in v2.5.0 (Enterprise Readiness PRD Complete)

- 🏢 **Multi-Tenant Architecture & 5-Tier RBAC**: Complete tenant data isolation (`sentinel/tenancy.py`), scoped queries, tenant switching, and role-based permissions (`admin`, `auditor`, `compliance_officer`, `engineer`, `viewer`).
- 📜 **OPA-Compliant Policy-as-Code Engine**: In-process policy evaluator (`sentinel/policy.py`) supporting Rego-like declarative rules, standard library comparisons, and multi-control compliance assertions.
- 🌳 **Merkle Tree Cryptographic Evidence Vault**: Append-only tamper-evident audit ledger (`sentinel/vault.py`) with cryptographic inclusion proofs, root verification, and automated sealing.
- 🏢 **Vendor Risk Management (CC9.2)**: Automated vendor tiering (Tier 1/2/3), SOC 2 / ISO 27001 certificate tracking, expiration SLA monitoring, and assessment scoring (`sentinel/vendor_risk.py`).
- 👥 **User Access Reviews (CC6.1–CC6.3)**: Automated periodic entitlement review campaigns, reviewer sign-off workflows, deprovisioning audit trails, and campaign progress tracking (`sentinel/access_review.py`).
- 🔔 **Multi-Channel Alerting & Incident Escalation**: Configurable notification routing (`sentinel/notifications.py`) to Slack, Microsoft Teams, PagerDuty, and custom HMAC-signed webhooks with rate limiting and deduplication.
- 🚪 **Auditor Portal & Time-Bounded Audit Rooms**: Secure time-expiring auditor rooms (`sentinel/audit_room.py`) with granular control mapping (CC1.1–CC9.9), scoped token authentication, full access auditing, and 1-click auditor ZIP package export.
- 🐶 **Dogfooding Self-Attestation Engine**: Continuous self-audit engine (`sentinel/dogfood.py`) verifying SOC2-Sentinel's internal security architecture against TSC criteria (CC6.1, CC6.7, CC7.1/CC7.2, CC8.1, CC9.2).
- 🛡️ **Public & Auditor Trust Center**: Real-time compliance profile generator (`sentinel/trust_center.py`) with public subprocessor directories, security metric dials, and embeddable standalone HTML view (`GET /trust-center`).
- 📡 **Enterprise SIEM Log Exporter & RFC 5424 Forwarder**: Live security event streaming (`sentinel/siem.py`) supporting RFC 5424 Syslog, Elastic Common Schema (ECS), Splunk HEC, Datadog Logs API, and NDJSON file export.
- 🚀 **Embedded Interactive Web Dashboard**: Launch a modern, glassmorphic dark-mode web application and continuous monitoring daemon (`sentinel serve`) with native multithreaded REST API and zero external web framework dependencies.
- 💻 **Standalone Windows Distribution**: Pre-compiled single-binary `bin/sentinel.exe` with interactive double-click terminal launcher (zero Python or pip setup required).

---

## ⚡ Quick Start Options

For complete step-by-step instructions, see the comprehensive [DIRECTIONS.md](DIRECTIONS.md) guide.

### Option A: Standalone Windows Executable (No Python Required)

1. Download and extract `dist\SOC2-Sentinel-Toolkit-v2.5.0-Windows.zip`.
2. Double-click `bin\sentinel.exe` for the interactive menu, or run via PowerShell:
```powershell
# Run full mock demo
.\bin\sentinel.exe run-all --provider mock

# Launch interactive web dashboard & REST API
.\bin\sentinel.exe serve --port 8443
```

### Option B: Python Virtual Environment (Developer / CI/CD)

```powershell
# 1. Setup virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt
pip install -e .

# 3. Launch embedded web dashboard
sentinel serve
```

The Web Dashboard opens automatically at `http://127.0.0.1:8443` featuring live scorecards, real-time collection console, evidence explorer, drift detection, trust center, and cloud onboarding wizard.

---

## ☁️ Tri-Cloud & Mock Parity

SOC2 Sentinel implements strict honest failure semantics (`collection_quality: "complete" | "partial" | "failed"` with structured `errors[]`).

| Provider | Collection Flag | Setup Documentation | Authentication Mechanism |
|:---|:---:|:---|:---|
| **Mock (Offline Demo)** | `--provider mock` | *None required (instant demo)* | Built-in offline fixtures |
| **Amazon Web Services** | `--provider aws` | [docs/AWS_IAM_POLICY.json](docs/AWS_IAM_POLICY.json) | Standard AWS CLI / Environment Variables |
| **Google Cloud Platform** | `--provider GCP` | [docs/GCP_SETUP.md](docs/GCP_SETUP.md) | Application Default Credentials (ADC) / SA Key |
| **Microsoft Azure** | `--provider azure` | [docs/AZURE_SETUP.md](docs/AZURE_SETUP.md) | Azure CLI / Service Principal Environment Variables |

---

## 🛡️ The 7 Core Automated Collectors

| Control ID | Collector Module | Domain / Capabilities Evaluated |
|:---:|:---|:---|
| **CC6.1** | `iam_access_review` | Deprovisioning SLA, orphaned identities (>90d inactive), privileged standing access, JIT elevation recommendations. |
| **CC7.1** | `log_aggregator` | CloudTrail / Activity Logs / Audit Sinks, continuous log ingestion, retention SLA (≥365d), CUI event capture. |
| **CC6.2** | `config_drift` | Unrestricted 0.0.0.0/0 security groups, unapproved infrastructure changes, MFA enforcement rate, baseline drift. |
| **C1.2** | `encryption_status` | Storage volumes/databases encrypted at rest, TLS 1.2+ transit enforcement, KMS key rotation, FIPS 140-2/3 validation. |
| **C1.4** | `retention_check` | Storage bucket lifecycle policies, automated data purge expiration rules, secure disposal verification. |
| **A1.2** | `resilience_testing` | 24-hour backup job execution, RDS / Cloud SQL snapshot age, 90-day restore testing SLA, RTO/RPO target verification. |
| **ZT-1** | `zt_continuous_verification` | Continuous dynamic verification across Identity, Device, Network, Application, Data, Visibility, and Automation pillars. |

---

## 📋 Comprehensive Enterprise CLI Commands

### Core Collection & Scoring
```powershell
# 1. Launch Web Dashboard & Continuous Monitoring Daemon
sentinel serve --port 8443

# 2. Run all evidence collectors
sentinel run-all --provider mock

# 3. Evaluate multi-framework compliance posture
sentinel scorecard

# 4. Detect automated configuration & compliance drift
sentinel drift

# 5. Preflight cloud diagnostics & minimal IAM policy fixes
sentinel onboarding --provider aws

# 6. Cryptographically verify evidence authenticity
sentinel verify evidence

# 7. Generate 1-Click Executive Audit Pack (HTML + signed ZIP)
sentinel audit-pack evidence
```

### Merkle Vault & Evidence Provenance (Phase 2)
```powershell
# Ingest evidence into tamper-evident Merkle tree vault
sentinel vault ingest evidence/

# Verify Merkle cryptographic integrity & generate inclusion proofs
sentinel vault verify

# Query immutable vault status
sentinel vault status
```

### Vendor Risk Management CC9.2 & Access Reviews CC6.1 (Phase 2)
```powershell
# Register vendor and record SOC 2 / ISO assessment
sentinel vendor-risk add --name "AWS" --tier 1 --soc2-status "Valid" --soc2-expiry "2027-12-31"

# Check upcoming vendor review expirations
sentinel vendor-risk check-expirations --within-days 90

# Launch quarterly user access review campaign
sentinel access-review create --title "Q3 2026 Privilege Review" --deadline "2026-10-31"

# Record manager sign-off on access entitlement
sentinel access-review review --campaign-id "<id>" --user "alice@example.com" --action approve
```

### Auditor Rooms, Dogfooding, Trust Center & SIEM (Phase 3)
```powershell
# Create a 30-day time-bounded auditor room
sentinel audit-room create --name "FY26 Type II Audit" --auditor "Assessor Corp" --email "auditor@assessor.com" --days 30

# Export complete auditor ZIP evidence package
sentinel audit-room export-package --room-id "<id>" --output ./audit_package.zip

# Run self-attestation dogfooding engine
sentinel dogfood run

# Generate standalone Public / Auditor Trust Center HTML
sentinel trust-center export --output ./trust_center.html

# Stream or export security audit logs to SIEM (RFC 5424, ECS, Splunk, Datadog)
sentinel siem export --format ecs --output ./siem_logs.ndjson
```

---

## 🧪 Testing & Code Quality

SOC2 Sentinel enforces strict continuous quality gates:

```powershell
# Run full Pytest test suite with code coverage
pytest --cov=sentinel --cov-report=term-missing --basetemp=.pytest_temp

# Linting & code style (Ruff)
ruff check sentinel tests

# Static type checking (Mypy)
mypy sentinel

# Security vulnerability analysis (Bandit)
bandit -r sentinel -ll
```

- **Pytest**: 239 passed, 1 skipped in ~24s.
- **Coverage**: 81.45% (strictly exceeds ≥80.0% mandate).
- **Ruff**: 0 errors / clean.
- **Mypy**: 0 errors across 82 source files.
- **Bandit**: 0 high/medium issues.

---

## 📁 Repository Structure

```
soc2-sentinel/
├── bin/
│   └── sentinel.exe                  # Standalone Windows executable (73.7 MB)
├── data/
│   ├── cmmc-l2-controls-110.csv      # Complete 110 CMMC L2 practices
│   ├── evidence-schema.json          # Strict JSON schema for evidence payloads
│   └── zero-trust-pillars.csv        # CISA Zero Trust pillar mapping
├── dist/
│   └── SOC2-Sentinel-Toolkit-*.zip   # Release distribution archive
├── docs/
│   ├── AWS_IAM_POLICY.json           # Minimal AWS read-only IAM policy
│   ├── GCP_SETUP.md                  # GCP service account setup & custom roles
│   ├── AZURE_SETUP.md                # Azure app registration & permissions
│   ├── SECURITY.md                   # Threat model & cryptographic provenance
│   └── INCIDENT_RESPONSE.md          # Compromised evidence & tampered manifest playbook
├── policies/                         # 17 enterprise-ready policy templates
├── scripts/
│   └── build-consumer-package.ps1    # Automated packaging & smoke-testing script
├── sentinel/
│   ├── collectors/                   # 7 automated evidence collectors
│   ├── dashboard/                    # Embedded web UI & native REST server
│   ├── providers/                    # Tri-cloud providers (AWS, GCP, Azure, Mock)
│   ├── access_review.py              # User access review campaigns (CC6.1-CC6.3)
│   ├── audit_room.py                 # Auditor portal & time-bounded rooms
│   ├── cli.py                        # Unified command-line interface & interactive menu
│   ├── daemon.py                     # Continuous monitoring background worker
│   ├── dogfood.py                    # Self-attestation dogfooding engine
│   ├── drift.py                      # Baseline comparison & configuration drift engine
│   ├── integrity.py                  # Cryptographic SHA-256 digests & HMAC signatures
│   ├── notifications.py              # Multi-channel alerting (Slack, Teams, PagerDuty, Webhooks)
│   ├── onboarding.py                 # Preflight permissions & minimal IAM generator
│   ├── policy.py                     # OPA-compliant in-process policy engine
│   ├── reporting.py                  # Standalone HTML report & ZIP audit pack exporter
│   ├── scoring.py                    # Multi-framework compliance scoring engine
│   ├── siem.py                       # SIEM log exporter & RFC 5424 forwarder
│   ├── tenancy.py                    # Multi-tenant isolation & 5-tier RBAC
│   ├── trust_center.py               # Enterprise trust center & subprocessor portal
│   ├── vault.py                      # Merkle tree cryptographic evidence vault
│   └── vendor_risk.py                # Third-party vendor risk management (CC9.2)
├── tests/                            # Comprehensive unit & integration test suite (239 tests)
├── DIRECTIONS.md                     # Step-by-step user and operator guide
├── pyproject.toml                    # Package metadata & build configuration
├── requirements.txt                  # Locked production runtime dependencies
└── requirements-dev.txt              # Development, test, and packaging tooling
```

---

## ⚖️ Legal Disclaimer

This toolkit provides policy templates, operational procedures, and evidence automation software. It is **not legal advice** and does **not** guarantee certification, audit pass, C3PAO approval, or DFARS reporting compliance. SOC2 Sentinel does not file DIBNet reports or detect live intrusions. Buyers are responsible for accurate implementation and assessor relationships.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full details.