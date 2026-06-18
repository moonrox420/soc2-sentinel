from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.config")


def config_and_auth_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure config/auth snapshot")
    open_http = 0
    weak_tls = 0
    mfa_registered = 0
    mfa_total = 0

    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        rg_client = ResourceGraphClient(ctx.credential)
        query = QueryRequest(
            subscriptions=[ctx.subscription_id],
            query="""
            Resources
            | where type =~ 'microsoft.network/networksecuritygroups'
            | mvexpand rule=properties.securityRules
            | where rule.properties.access == 'Allow' and rule.properties.destinationPortRange == '80'
            | summarize openHttp=count()
            """,
        )
        ctx.attempt()
        result = call_with_retry(
            lambda: rg_client.resources(query),
            operation="azure_resource_graph_nsg",
        )
        ctx.succeed()
        for row in result.data:
            open_http = int(row.get("openHttp", 0))
    except Exception as exc:
        ctx.record_error("resourcegraph", exc)

    mfa_data = ctx.graph_get(
        "/reports/authenticationMethods/userRegistrationDetails?$top=999"
    )
    if mfa_data:
        for user in mfa_data.get("value", []):
            mfa_total += 1
            if user.get("isMfaRegistered"):
                mfa_registered += 1

    mfa_pct: float | None = None
    if mfa_total > 0:
        mfa_pct = round((mfa_registered / mfa_total) * 100, 1)
    elif mfa_data is None:
        mfa_pct = None
    else:
        mfa_pct = 0.0

    return finalize_snapshot(
        {
            "mfa_enforcement_percent": mfa_pct if mfa_pct is not None else 0.0,
            "weak_auth_methods": mfa_total - mfa_registered if mfa_total else 0,
            "open_http_listeners": open_http,
            "weak_tls_listeners": weak_tls,
            "unapproved_changes": 0,
            "changes_missing_rollback_test": 0,
            "issues": open_http + weak_tls,
            "warnings": 0 if mfa_pct == 100.0 else 1,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )