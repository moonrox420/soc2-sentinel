from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.retention")


def retention_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP retention snapshot")
    missing_lifecycle = 0
    findings: list[dict[str, str]] = []

    try:
        from google.cloud import storage

        client = storage.Client(project=ctx.project_id)
        ctx.attempt()
        buckets = call_with_retry(lambda: list(client.list_buckets()), operation="gcp_list_buckets")
        ctx.succeed()
        for bucket in buckets:
            bucket.reload()
            if not bucket.lifecycle_rules:
                missing_lifecycle += 1
                findings.append({"resource": f"gs://{bucket.name}", "issue": "no lifecycle rules"})
    except Exception as exc:
        ctx.record_error("storage", exc)

    return finalize_snapshot(
        {
            "buckets_missing_lifecycle": missing_lifecycle,
            "objects_past_retention": missing_lifecycle,
            "findings": findings,
            "notes": "objects_past_retention mirrors buckets_missing_lifecycle.",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )