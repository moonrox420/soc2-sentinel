# Evidence Key Rotation (v2.5)

## Encryption keys

1. Generate a new `SENTINEL_EVIDENCE_KEY` in your vault.
2. Set `SENTINEL_EVIDENCE_KEY_ID=2026-06-rotation-1` (any stable string).
3. New collections write SSENC2 blobs with the new `key_id` in the header.
4. Decrypt old evidence with the previous key — match `key_id` from the blob header to vault entry.

## HMAC keys

1. Rotate `SENTINEL_HMAC_KEY` on the same schedule as encryption keys.
2. Re-run collectors to produce new manifests with the new HMAC.
3. Old manifests verify only with the HMAC active at collection time — archive old HMAC values for audit retention.

## Startup validation

When `evidence.encrypt: true` in `sentinel.yaml`, `sentinel validate` fails fast if keys are missing — rotation must update env vars **before** the next scheduled run.