# SOC2 Sentinel Security Model (v2.4)

## Threat model

SOC2 Sentinel runs on operator workstations with read-only cloud credentials. Primary risks:

- Path traversal via malicious `control_id` or artifact names
- Plaintext evidence containing IAM identities or resource metadata
- Tampering with evidence after collection
- Cloud API failures producing incomplete audit artifacts

## Controls implemented

| Control | Module |
|---------|--------|
| Path sanitization | `sentinel/validation.py` |
| Atomic evidence writes | `sentinel/output.py` |
| Restrictive file modes (Unix) | `sentinel/security.py` |
| Optional AES-256-GCM encryption | `SENTINEL_EVIDENCE_KEY` + config |
| SHA-256 manifest per run | `sentinel/integrity.py` |
| Optional HMAC tamper tag | `SENTINEL_HMAC_KEY` |
| Audit JSONL trail | `evidence/.sentinel-audit.jsonl` |
| CSV formula injection guard | `sentinel/security.py` |
| Provider credential preflight | AWS/GCP/Azure providers |
| Retry/timeouts for cloud APIs | `sentinel/cloud.py` |

## Key management

- `SENTINEL_EVIDENCE_KEY` — 32+ character secret for encryption-at-rest (opt-in)
- `SENTINEL_HMAC_KEY` — separate secret for manifest HMAC (recommended for regulated buyers)

Do not commit keys. Use environment variables or a team vault.

## Chain of custody

Each collector run writes:

1. `report.json` (or `.enc` when encryption enabled)
2. Supporting artifacts listed only if actually written
3. `manifest.json` with SHA-256 per file
4. Audit event in `.sentinel-audit.jsonl`

## Future hooks (not in v2.4)

- Scheduled evidence rolls (cron / CI)
- SIEM and incident tracker integrations
- Jira/ServiceNow POA&M sync