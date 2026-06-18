from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.logging")


def log_monitoring_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS log monitoring snapshot")
    trails = ctx.client("cloudtrail")
    cfg = ctx.client("config")
    logs = ctx.client("logs")

    active_trails = 0
    multi_region = 0
    findings: list[dict[str, str]] = []
    trail_list: list[dict[str, Any]] = []
    recorder_on = False
    max_gap_hours: float | None = None

    trail_resp = ctx.call(
        "cloudtrail",
        "aws_describe_trails",
        lambda: trails.describe_trails(includeShadowTrails=False),
    )
    if trail_resp:
        trail_list = trail_resp.get("trailList", [])
        for trail in trail_list:
            if trail.get("IsMultiRegionTrail"):
                multi_region += 1
            status_resp = ctx.call(
                "cloudtrail",
                "aws_trail_status",
                lambda t=trail: trails.get_trail_status(Name=t["TrailARN"]),
            )
            if status_resp:
                if status_resp.get("IsLogging"):
                    active_trails += 1
                    latest = status_resp.get("LatestDeliveryTime")
                    if latest:
                        gap = (datetime.now(timezone.utc) - latest).total_seconds() / 3600
                        max_gap_hours = gap if max_gap_hours is None else max(max_gap_hours, gap)
                else:
                    findings.append(
                        {"resource": trail.get("Name", "trail"), "issue": "trail not logging"}
                    )

    recorder_resp = ctx.call(
        "config",
        "aws_config_recorders",
        lambda: cfg.describe_configuration_recorders(),
    )
    if recorder_resp:
        recorders = recorder_resp.get("ConfigurationRecorders", [])
        recorder_on = any(r.get("recordingGroup", {}).get("allSupported") for r in recorders)

    log_groups_with_retention = 0
    log_groups_total = 0
    lg_resp = ctx.call("logs", "aws_describe_log_groups", lambda: logs.describe_log_groups(limit=50))
    if lg_resp:
        for group in lg_resp.get("logGroups", []):
            log_groups_total += 1
            if group.get("retentionInDays"):
                log_groups_with_retention += 1

    total_trails = len(trail_list)
    if total_trails == 0:
        coverage: float | None = None
    else:
        coverage = round((active_trails / total_trails) * 100, 1)

    cui_events = _sample_cui_events(ctx, trails)

    data: dict[str, Any] = {
        "active_trails": active_trails,
        "multi_region_trails": multi_region,
        "config_recorder_all_supported": recorder_on,
        "log_coverage_percent": coverage,
        "max_gap_hours": max_gap_hours,
        "log_groups_with_retention": log_groups_with_retention,
        "log_groups_checked": log_groups_total,
        "critical_control_failures_30d": len(findings),
        "findings": findings,
        "cui_relevant_events": cui_events,
        "cui_retention_days": 365,
        "attck_summary": _attck_summary(cui_events),
    }
    if coverage is None:
        ctx.errors.append(
            {
                "code": "NoTrails",
                "message": "No CloudTrail trails found; log_coverage_percent unavailable",
                "service": "cloudtrail",
                "severity": "high",
            }
        )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )


def _sample_cui_events(ctx: AwsClients, trails_client) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    resp = ctx.call(
        "cloudtrail",
        "aws_lookup_events",
        lambda: trails_client.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": "cui"}],
            MaxResults=10,
        ),
    )
    if resp:
        for event in resp.get("Events", []):
            events.append(
                {
                    "timestamp": event.get("EventTime", datetime.now(timezone.utc)).isoformat(),
                    "resource": event.get("Resources", [{}])[0].get("ResourceName", "unknown"),
                    "action": event.get("EventName", "unknown"),
                    "principal": event.get("Username", "unknown"),
                    "attck_tags": ["T1078"],
                }
            )
    return events


def _attck_summary(events: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for event in events:
        for tag in event.get("attck_tags", []):
            summary[tag] = summary.get(tag, 0) + 1
    return summary