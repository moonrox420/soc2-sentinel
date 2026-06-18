from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.logging")


def log_monitoring_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure log monitoring snapshot")
    findings: list[dict[str, str]] = []
    with_diagnostics = 0
    total_resources = 0
    coverage: float | None = None

    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        rg_client = ResourceGraphClient(ctx.credential)
        query = QueryRequest(
            subscriptions=[ctx.subscription_id],
            query="""
            Resources
            | summarize total=count(), withDiag=countif(isnotempty(properties.diagnosticSettings))
            """,
        )
        ctx.attempt()
        result = call_with_retry(
            lambda: rg_client.resources(query),
            operation="azure_resource_graph_diagnostics",
        )
        ctx.succeed()
        for row in result.data:
            total_resources = int(row.get("total", 0))
            with_diagnostics = int(row.get("withDiag", 0))
        if total_resources > 0:
            coverage = round((with_diagnostics / total_resources) * 100, 1)
    except Exception as exc:
        ctx.record_error("resourcegraph", exc)

    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor = MonitorManagementClient(ctx.credential, ctx.subscription_id)
        ctx.attempt()
        settings = call_with_retry(
            lambda: list(monitor.diagnostic_settings.list("subscriptions/" + ctx.subscription_id)),
            operation="azure_subscription_diagnostics",
        )
        ctx.succeed()
        if not settings:
            findings.append({"resource": "subscription", "issue": "no subscription diagnostic settings"})
    except Exception as exc:
        ctx.record_error("monitor", exc)

    data: dict[str, Any] = {
        "active_trails": with_diagnostics,
        "multi_region_trails": 0,
        "config_recorder_all_supported": with_diagnostics > 0,
        "log_coverage_percent": coverage,
        "max_gap_hours": 0 if with_diagnostics else None,
        "critical_control_failures_30d": len(findings),
        "findings": findings,
        "cui_relevant_events": [],
        "cui_retention_days": 365,
        "attck_summary": {},
        "resources_checked": total_resources,
    }
    if coverage is None:
        ctx.errors.append(
            api_error(
                "CoverageUnavailable",
                "Could not compute log_coverage_percent from Resource Graph",
                service="monitor",
                severity="high",
            )
        )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )