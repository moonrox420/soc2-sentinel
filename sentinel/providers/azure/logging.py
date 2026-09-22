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
    subscription_diagnostic_settings = 0
    coverage: float | None = None

    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor = MonitorManagementClient(ctx.credential, ctx.subscription_id)
        ctx.attempt()
        settings = call_with_retry(
            lambda: list(monitor.diagnostic_settings.list("subscriptions/" + ctx.subscription_id)),
            operation="azure_subscription_diagnostics",
        )
        ctx.succeed()
        subscription_diagnostic_settings = len(settings)
        if not settings:
            findings.append({"resource": "subscription", "issue": "no subscription diagnostic settings"})
    except Exception as exc:
        ctx.record_error("monitor", exc)

    data: dict[str, Any] = {
        "active_trails": subscription_diagnostic_settings,
        "multi_region_trails": 0,
        "config_recorder_all_supported": subscription_diagnostic_settings > 0,
        "log_coverage_percent": coverage,
        "max_gap_hours": None,
        "critical_control_failures_30d": len(findings),
        "findings": findings,
        "cui_relevant_events": [],
        "cui_retention_days": None,
        "attck_summary": {},
        "subscription_diagnostic_settings_count": subscription_diagnostic_settings,
        "resources_checked": None,
    }
    if coverage is None:
        ctx.errors.append(
            api_error(
                "CoverageUnavailable",
                "Subscription diagnostic settings do not prove per-resource logging coverage",
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