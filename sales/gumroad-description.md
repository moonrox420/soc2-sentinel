# SOC2 Sentinel Toolkit — Gumroad Product Description

## Headline

**SOC2 Sentinel Toolkit v2.5** — Tri-cloud live evidence collectors for AWS, GCP, and Azure. Honest audit-grade output with structured `errors[]` and `collection_quality`. Mock mode for offline demo only.

---

## Short description (160 chars)

v2.5: Live AWS/GCP/Azure APIs for all 7 collectors. Structured errors, HKDF encryption, sentinel validate/verify. Mock = demo only. No cert guarantee.

---

## Full description

**SOC2 Sentinel Toolkit v2.5.0** automates evidence collection for SOC 2, CMMC L2, DFARS, ATT&CK, and Zero Trust readiness.

### What's new in v2.5

- **Tri-cloud live collectors** — all 7 snapshots use real APIs on AWS, GCP, and Azure (no fabricated backup hours or log coverage %)
- **Honest failure** — every report includes `collection_quality` and machine-readable `errors[]`
- **`sentinel validate`** — config + credential preflight before cloud API calls
- **`sentinel verify`** — SHA-256 manifest + optional HMAC tamper check
- **HKDF encryption (SSENC2)** with `key_id` for rotation
- **80%+ test coverage** CI gate; 120 automated tests

### Mock vs cloud

- `--provider mock` uses bundled fixtures for **offline demo only**
- Gumroad copy never implies mock output is cloud evidence
- Production runs require read-only IAM per included setup guides

### Collectors (all live on AWS/GCP/Azure)

`iam_access_review`, `log_aggregator`, `config_drift`, `encryption_status`, `retention_check`, `resilience_testing`, `zt_continuous_verification`

### Not included (documented hooks only)

Jira sync, SIEM webhooks, cron scheduler — no fake stubs.

### Disclaimer

Supports compliance **readiness** and self-assessment. Does not guarantee certification or replace a C3PAO assessor.