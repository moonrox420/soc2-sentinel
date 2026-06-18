# SOC2 Sentinel Security Model (v2.5)

## Threat model

| Threat | Impact | v2.5 mitigation |
|--------|--------|-----------------|
| Insider modifies evidence post-collection | Audit failure | SHA-256 manifest + optional HMAC; `sentinel verify` |
| Replay of stale evidence | False compliance | Manifest includes `toolkit_version` + `collection_timestamp` |
| Concurrent runs corrupt evidence | Data loss | `portalocker` per control directory |
| Compromised cloud credentials | Data exfiltration | Read-only IAM; credential preflight; audit JSONL |
| Path traversal in control IDs | Arbitrary file write | Strict sanitization + allowlist (default on) |
| Plaintext PII on disk | Privacy breach | Optional encryption (HKDF + AES-GCM); PII redaction |
| Manifest deletion | Integrity loss | Backup copy under `evidence/<date>/manifests/` |
| API partial failure buried in notes | False green status | Structured `errors[]` + `collection_quality` |

## Controls implemented

| Control | Module |
|---------|--------|
| Path sanitization + strict allowlist | `sentinel/validation.py` |
| Startup config validation | `sentinel/config.py` → `validate()` |
| Atomic evidence writes + file lock | `sentinel/output.py` |
| HKDF key derivation (SSENC2) | `sentinel/security.py` |
| HMAC-enforced decrypt | `SENTINEL_HMAC_KEY` + manifest |
| Audit JSONL with quality metrics | `sentinel/audit.py` |
| Provider credential preflight | `sentinel/providers/` |
| Retry/timeouts for cloud APIs | `sentinel/cloud.py` |

## Key management

| Variable | Purpose |
|----------|---------|
| `SENTINEL_EVIDENCE_KEY` | AES-GCM encryption secret (opt-in) |
| `SENTINEL_EVIDENCE_KEY_ID` | Key rotation identifier embedded in SSENC2 header |
| `SENTINEL_EVIDENCE_KEY_FILE` | Alternative to env var (path to secret file) |
| `SENTINEL_HMAC_KEY` | Manifest HMAC (recommended for regulated buyers) |

Store secrets in AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager — never in `sentinel.yaml`.

## Permission matrix

- **AWS:** `docs/AWS_IAM_POLICY.json` — Backup, ACM, Config compliance, credential report
- **GCP:** `docs/GCP_SETUP.md` — custom role `soc2SentinelViewer`
- **Azure:** `docs/AZURE_SETUP.md` — Graph app + Resource Graph Reader

## Log shipping

Use `--log-file` for structured JSON logs. Forward to CloudWatch, Azure Monitor, or syslog per your SIEM runbook.

## Future hooks (documented only — no stubs)

- Jira/ServiceNow POA&M sync
- Scheduled cron evidence rolls
- Live SIEM webhooks
- Multi-signature evidence
- `sentinel access-log` (OS-level access auditing)