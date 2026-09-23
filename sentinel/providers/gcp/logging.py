from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.logging")


def log_monitoring_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP log monitoring snapshot")
    sinks: list[Any] = []
    buckets: list[Any] = []
    findings: list[dict[str, str]] = []
    cui_events: list[dict[str, Any]] = []

    try:
        from google.cloud import logging as cloud_logging
        from google.cloud.logging_v2.services.config_service_v2 import (
            ConfigServiceV2Client,
        )

        credentials = ctx.get_credentials()
        sink_client = cloud_logging.Client(
            project=ctx.project_id,
            credentials=credentials,
        )
        config_client = ConfigServiceV2Client(credentials=credentials)

        ctx.attempt()
        sinks = call_with_retry(
            lambda: list(sink_client.list_sinks()),
            operation="gcp_list_log_sinks",
        )
        ctx.succeed()

        ctx.attempt()
        buckets = call_with_retry(
            lambda: list(
                config_client.list_buckets(
                    request={"parent": f"projects/{ctx.project_id}/locations/-"}
                )
            ),
            operation="gcp_list_log_buckets",
        )
        ctx.succeed()
    except Exception as exc:
        ctx.record_error("logging", exc)

    required_sink = any(
        getattr(sink, "name", "").endswith("_Default")
        or "_Required" in getattr(sink, "name", "")
        for sink in sinks
    )
    if not sinks:
        findings.append(
            {
                "resource": "logging",
                "issue": "no log sinks configured",
            }
        )

    bucket_retention_days = sorted(
        {
            int(days)
            for bucket in buckets
            if (days := getattr(bucket, "retention_days", None)) is not None
        }
    )

    try:
        from google.cloud import logging as cloud_logging

        entry_client = cloud_logging.Client(
            project=ctx.project_id,
            credentials=ctx.get_credentials(),
        )

        ctx.attempt()
        entries = call_with_retry(
            lambda: list(
                entry_client.list_entries(
                    filter_='protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"',
                    max_results=10,
                    page_size=10,
                )
            ),
            operation="gcp_list_log_entries",
        )
        ctx.succeed()

        for entry in entries:
            cui_events.append(
                {
                    "timestamp": (
                        entry.timestamp.isoformat() if entry.timestamp else None
                    ),
                    "resource": getattr(entry, "resource", None),
                    "action": getattr(entry, "severity", "unknown"),
                    "principal": getattr(entry, "insert_id", "unknown"),
                    "attck_tags": ["T1078"],
                }
            )
    except Exception as exc:
        ctx.record_error("logging", exc, code="EntriesListDenied")

    data: dict[str, Any] = {
        "active_trails": len(sinks),
        "multi_region_trails": sum(
            1
            for sink in sinks
            if getattr(sink, "destination", "").startswith(
                "storage.googleapis.com"
            )
        ),
        "config_recorder_all_supported": required_sink,
        "log_coverage_percent": None,
        "max_gap_hours": None,
        "critical_control_failures_30d": len(findings),
        "findings": findings,
        "cui_relevant_events": cui_events,
        "cui_retention_days": None,
        "logging_sinks_count": len(sinks),
        "logging_buckets_count": len(buckets),
        "required_sink_present": required_sink,
        "log_bucket_retention_days": bucket_retention_days,
        "attck_summary": {},
    }

    ctx.errors.append(
        api_error(
            "CoverageUnavailable",
            "Log sink and bucket counts do not prove per-resource logging coverage",
            service="logging",
            severity="high",
        )
    )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )
