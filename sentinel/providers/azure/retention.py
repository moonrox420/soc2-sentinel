from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.retention")


def retention_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure retention snapshot")
    missing_lifecycle = 0
    findings: list[dict[str, str]] = []

    try:
        ctx.attempt()
        accounts = call_with_retry(
            lambda: list(ctx.storage.storage_accounts.list()),
            operation="azure_list_storage_accounts",
        )
        ctx.succeed()
        for account in accounts:
            rg = account.id.split("/")[4]
            mgmt = call_with_retry(
                lambda a=account, r=rg: ctx.storage.management_policies.get(r, a.name),
                operation="azure_management_policies",
            )
            if not mgmt or not mgmt.policy or not mgmt.policy.rules:
                missing_lifecycle += 1
                findings.append(
                    {"resource": account.name, "issue": "no storage management policy"}
                )
    except Exception as exc:
        ctx.record_error("storage", exc)

    return finalize_snapshot(
        {
            "accounts_missing_lifecycle": missing_lifecycle,
            "objects_past_retention": missing_lifecycle,
            "findings": findings,
            "notes": "objects_past_retention mirrors accounts_missing_lifecycle.",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )