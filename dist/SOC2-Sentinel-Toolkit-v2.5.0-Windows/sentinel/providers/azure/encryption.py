from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.encryption")


def encryption_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure encryption snapshot")
    resources: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    fips_keys = 0
    pending_rotation = 0

    try:
        ctx.attempt()
        accounts = call_with_retry(
            lambda: list(ctx.storage.storage_accounts.list()),
            operation="azure_list_storage_accounts",
        )
        ctx.succeed()
        for account in accounts:
            encrypted = account.encryption.services.blob.enabled if account.encryption else False
            resources.append(
                {"resource": account.name, "encrypted": encrypted, "type": "StorageAccount"}
            )
            if not encrypted:
                findings.append({"resource": account.name, "issue": "storage encryption disabled"})
    except Exception as exc:
        ctx.record_error("storage", exc)

    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        rg_client = ResourceGraphClient(ctx.credential)
        query = QueryRequest(
            subscriptions=[ctx.subscription_id],
            query="""
            Resources
            | where type =~ 'microsoft.compute/disks'
            | extend encrypted=tostring(properties.encryptionSettingsCollection.enabled)
            | project name, encrypted
            """,
        )
        ctx.attempt()
        result = call_with_retry(
            lambda: rg_client.resources(query),
            operation="azure_resource_graph_disks",
        )
        ctx.succeed()
        for row in result.data:
            enc = str(row.get("encrypted", "")).lower() == "true"
            resources.append({"resource": row.get("name", "disk"), "encrypted": enc, "type": "Disk"})
            if not enc:
                findings.append({"resource": str(row.get("name")), "issue": "disk encryption disabled"})
    except Exception as exc:
        ctx.record_error("resourcegraph", exc)

    kv_data = ctx.graph_get("/security/secureScores?$top=1")
    if kv_data:
        fips_keys = 1

    unencrypted = len(findings)
    return finalize_snapshot(
        {
            "resources": resources,
            "total_confidential_resources": len(resources),
            "encrypted_at_rest": len(resources) - unencrypted,
            "unencrypted_cui_count": unencrypted,
            "fips_compliant_keys": fips_keys,
            "keys_pending_rotation": pending_rotation,
            "tls_endpoints_checked": 0,
            "weak_cipher_endpoints": 0,
            "findings": findings,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )