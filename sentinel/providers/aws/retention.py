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

    repositories_checked = 0
    buckets_resp = ctx.call("s3", "aws_s3_list_buckets", lambda: s3.list_buckets())
    if buckets_resp:
        buckets_list = buckets_resp.get("Buckets", [])
        repositories_checked = len(buckets_list)
        for bucket in buckets_list:
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
                        {
                            "resource": f"s3://{name}",
                            "issue": "no lifecycle expiration rule",
                        }
                    )
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchLifecycleConfiguration":
                    ctx.succeed()
                    missing_lifecycle += 1
                    findings.append(
                        {
                            "resource": f"s3://{name}",
                            "issue": "missing lifecycle configuration",
                        }
                    )
                else:
                    ctx.record_access_denied("s3", exc)

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    return finalize_snapshot(
        {
            "repositories_checked": repositories_checked,
            "repositories_missing_lifecycle": missing_lifecycle,
            "buckets_missing_lifecycle": missing_lifecycle,
            "objects_past_retention": None,
            "retention_policy_cutoff": cutoff.isoformat().replace("+00:00", "Z"),
            "findings": findings,
            "notes": "Evaluated repository-level lifecycle expiration policies across active storage repositories.",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )
