# SOC2 Sentinel — Incident Response Playbook

## Compromised evidence key (`SENTINEL_EVIDENCE_KEY`)

1. Rotate the key immediately in your secrets manager.
2. Set `SENTINEL_EVIDENCE_KEY_ID` to a new identifier for future collections.
3. Existing SSENC2 blobs remain decryptable with the **old** key + matching `key_id` header.
4. Re-run affected collectors after rotation; compare manifest timestamps.

## Tampered manifest

1. Run `sentinel verify evidence/<date>/`.
2. If HMAC mismatch: treat evidence as untrusted; preserve disk image for forensics.
3. Re-collect from live cloud APIs; do not edit `report.json` manually.

## Compromised cloud read credentials

1. Disable the IAM role / service account used by Sentinel.
2. Review CloudTrail / Activity Log for API calls during the exposure window.
3. Issue new least-privilege credentials per `docs/AWS_IAM_POLICY.json` (or GCP/Azure guides).
4. Document in `.sentinel-audit.jsonl` review notes.

## Partial collection (`collection_quality: partial`)

1. Parse `errors[]` in `report.json` programmatically.
2. Fix missing permissions (see cloud setup docs).
3. Re-run single collector: `sentinel run <collector> --provider <cloud>`.
4. Do not mark control green until `collection_quality` is `complete`.