from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.encryption")


def encryption_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP encryption snapshot")
    resources: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    fips_keys = 0
    pending_rotation = 0

    try:
        from google.cloud.storage import Client as StorageClient

        client = StorageClient(project=ctx.project_id)
        ctx.attempt()
        buckets = call_with_retry(
            lambda: list(client.list_buckets()), operation="gcp_list_buckets"
        )
        ctx.succeed()
        for bucket in buckets:
            bucket.reload()
            has_cmek = bool(getattr(bucket, "default_kms_key_name", None))
            # GCS enforces server-side encryption at rest by default; CMEK provides customer-managed keys
            encrypted = True
            resources.append(
                {
                    "resource": f"gs://{bucket.name}",
                    "encrypted": encrypted,
                    "cmek_enabled": has_cmek,
                    "type": "GCS",
                }
            )
    except Exception as exc:
        ctx.record_error("storage", exc)

    keys_with_rotation = 0
    pending_rotation = 0

    try:
        from google.cloud import kms

        kms_client = kms.KeyManagementServiceClient()
        parent = f"projects/{ctx.project_id}/locations/-"
        ctx.attempt()
        keys = call_with_retry(
            lambda: list(kms_client.list_crypto_keys(request={"parent": parent})),
            operation="gcp_list_kms_keys",
        )
        ctx.succeed()
        for key in keys:
            if key.rotation_period:
                keys_with_rotation += 1
            else:
                pending_rotation += 1
    except Exception as exc:
        ctx.record_error("kms", exc)

    unencrypted = len(findings)
    return finalize_snapshot(
        {
            "resources": resources,
            "total_confidential_resources": len(resources),
            "encrypted_at_rest": len(resources) - unencrypted,
            "unencrypted_cui_count": unencrypted,
            "keys_with_rotation": keys_with_rotation,
            "keys_pending_rotation": pending_rotation,
            "fips_compliant_keys": None,
            "tls_endpoints_checked": 0,
            "weak_cipher_endpoints": 0,
            "findings": findings,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )
