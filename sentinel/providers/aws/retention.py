from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.retention")


def retention_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS retention snapshot")
    s3 = ctx.client("s3")
    missing_lifecycle = 0
    findings: list[dict[str, str]] = []

    buckets_resp = ctx.call("s3", "aws_s3_list_buckets", lambda: s3.list_buckets())
    if buckets_resp:
        for bucket in buckets_resp.get("Buckets", []):
            name = bucket["Name"]
            ctx.attempt()
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=name)
                ctx.succeed()
                rules = lifecycle.get("Rules", [])
                has_expiry = any(
                    r.get("Status") == "Enabled" and "Expiration" in r for r in rules
                )
                if not has_expiry:
                    missing_lifecycle += 1
                    findings.append(
                        {"resource": f"s3://{name}", "issue": "no lifecycle expiration rule"}
                    )
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchLifecycleConfiguration":
                    ctx.succeed()
                    missing_lifecycle += 1
                    findings.append(
                        {"resource": f"s3://{name}", "issue": "missing lifecycle configuration"}
                    )
                else:
                    ctx.record_access_denied("s3", exc)

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    return finalize_snapshot(
        {
            "buckets_missing_lifecycle": missing_lifecycle,
            "objects_past_retention": missing_lifecycle,
            "retention_policy_cutoff": cutoff.isoformat().replace("+00:00", "Z"),
            "findings": findings,
            "notes": "objects_past_retention mirrors buckets_missing_lifecycle (bucket-level lifecycle audit).",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )