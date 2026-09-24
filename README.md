# SOC2 Sentinel Toolkit v2.5.0

**Enterprise-grade continuous compliance automation platform & audit accelerator.**

Built for **SOC 2 Type II**, **NIST SP 800-171 / 800-172**, **CMMC 2.0 Level 2**, **DFARS 7012**, **MITRE ATT&CK**, and **CISA Zero Trust** compliance workflows.

[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-177%20passed-success.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-81.93%25-brightgreen.svg)](pyproject.toml)
[![Security: Bandit](https://img.shields.io/badge/security-bandit%20clean-brightgreen.svg)](sentinel/)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checker-mypy%20clean-blue.svg)](pyproject.toml)

---

## 🌟 What's New in v2.5.0

- 🚀 **Embedded Interactive Web Dashboard**: Launch a modern, glassmorphic dark-mode web application and continuous monitoring daemon (`sentinel serve` / `sentinel dashboard`) with native multithreaded REST API and zero heavy web framework bloat.
- 📊 **Multi-Framework Compliance Engine**: Simultaneous real-time compliance readiness evaluation for **SOC 2 Type II**, **NIST SP 800-171/172**, **CMMC 2.0 Level 2**, and **CISA Zero Trust Maturity Model**.
- 🔍 **Automated Configuration Drift Engine**: Compares successive runs to isolate regressions in IAM deprovisioning, MFA enforcement, open ingress rules, unapproved configuration changes, cryptographic coverage, and backup integrity.
- 📦 **1-Click Executive Audit Pack Exporter**: Generates standalone, zero-dependency printable HTML executive audit reports (`SOC2-Sentinel-Executive-Report-<date>.html`) and verified cryptographic ZIP archives (`SOC2-Sentinel-AuditPack-<date>.zip`).
- 🛠️ **Guided Cloud Onboarding**: Preflight permission diagnostics for AWS, GCP, and Azure with auto-generated minimal IAM policy statements (`sentinel onboarding`).
- 💻 **Standalone Windows Distribution**: Pre-compiled single-binary `bin/sentinel.exe` with interactive double-click terminal launcher (zero Python or pip setup required).
- 🛡️ **Tamper-Evident Cryptographic Provenance**: Deterministic SHA-256 evidence hashing, HMAC-SHA256 signatures, and atomic concurrent write locking via `portalocker`.

---

## ⚡ Quick Start Options

For complete step-by-step instructions, see the comprehensive [DIRECTIONS.md](DIRECTIONS.md) guide.

### Option A: Standalone Windows Executable (No Python Required)

1. Download and extract `dist\SOC2-Sentinel-Toolkit-v2.5.0-Windows.zip`.
2. Double-click `bin\sentinel.exe` for the interactive menu, or run via PowerShell:
```powershell
# Run full mock demo
.\bin\sentinel.exe run-all --provider mock

# Launch interactive web dashboard
.\bin\sentinel.exe serve
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

The Web Dashboard opens automatically at `http://127.0.0.1:8443` featuring live scorecards, real-time collection console, evidence explorer, drift detection, and cloud onboarding wizard.

---

## ☁️ Tri-Cloud & Mock Parity

SOC2 Sentinel implements strict honest failure semantics (`collection_quality: "complete" | "partial" | "failed"` with structured `errors[]`).

| Provider | Collection Flag | Setup Documentation | Authentication Mechanism |
|:---|:---:|:---|:---|
| **Mock (Offline Demo)** | `--provider mock` | *None required (instant demo)* | Built-in offline fixtures |
| **Amazon Web Services** | `--provider aws` | [docs/AWS_IAM_POLICY.json](docs/AWS_IAM_POLICY.json) | Standard AWS CLI / Environment Variables |
| **Google Cloud Platform** | `--provider gcp` | [docs/GCP_SETUP.md](docs/GCP_SETUP.md) | Application Default Credentials (ADC) / SA Key |
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

## 📋 Common CLI Commands

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

---

## 📊 Sample Compliance Scorecard

```json
{
  "provider": "mock",
  "overall_posture_score": 98.6,
  "soc2": {
    "framework_name": "SOC 2 Type II (Trust Services Criteria)",
    "overall_score": 98.6,
    "readiness_level": "Audit Ready",
    "pillar_scores": {
      "Security": 97.5,
      "Confidentiality": 100.0,
      "Availability": 100.0
    }
  },
  "nist": {
    "framework_name": "NIST SP 800-171 / 800-172",
    "overall_score": 98.6,
    "readiness_level": "Audit Ready"
  },
  "cmmc": {
    "framework_name": "CMMC 2.0 Level 2 (110 Controls)",
    "overall_score": 98.6,
    "readiness_level": "Audit Ready"
  },
  "zero_trust": {
    "framework_name": "CISA Zero Trust Maturity Model",
    "overall_score": 98.6,
    "readiness_level": "Audit Ready"
  }
}
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

- **Pytest**: 177 passed, 1 skipped.
- **Coverage**: 81.93% (strictly exceeds ≥80.0% mandate).
- **Ruff**: 0 errors / clean.
- **Mypy**: 0 errors across 66 source files.
- **Bandit**: 0 high/medium issues.

---

## 📁 Repository Structure

```
soc2-sentinel/
├── bin/
│   └── sentinel.exe                  # Standalone Windows executable
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
│   ├── scoring.py                    # Multi-framework compliance scoring engine
│   ├── drift.py                      # Baseline comparison & configuration drift engine
│   ├── onboarding.py                 # Preflight permissions & minimal IAM generator
│   ├── reporting.py                  # Standalone HTML report & ZIP audit pack exporter
│   ├── daemon.py                     # Continuous monitoring background worker
│   ├── integrity.py                  # Cryptographic SHA-256 digests & HMAC signatures
│   └── cli.py                        # Unified command-line interface & interactive menu
├── tests/                            # Comprehensive unit & integration test suite (177 tests)
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