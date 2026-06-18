from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.iam")


def _credential_report_days(iam, ctx: AwsClients) -> int | None:
    try:
        ctx.attempt()
        iam.generate_credential_report()
        report = iam.get_credential_report()
        ctx.succeed()
        content = report["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        max_age = 0
        for row in reader:
            for field in ("access_key_1_last_rotated", "access_key_2_last_rotated", "password_last_changed"):
                val = row.get(field, "N/A")
                if not val or val in {"N/A", "not_supported", "no_information"}:
                    continue
                try:
                    dt = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - dt).days
                    max_age = max(max_age, age)
                except ValueError:
                    continue
        return max_age if max_age > 0 else None
    except ClientError as exc:
        ctx.record_access_denied("iam", exc)
        return None


def iam_access_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS IAM access snapshot")
    iam = ctx.client("iam")
    users: list[dict[str, Any]] = []
    orphaned = 0
    privileged = 0

    pages = ctx.call("iam", "aws_iam_list_users", lambda: list(iam.get_paginator("list_users").paginate()))
    if pages:
        for page in pages:
            for user in page.get("Users", []):
                name = user["UserName"]
                keys_resp = ctx.call(
                    "iam",
                    "aws_iam_list_access_keys",
                    lambda u=name: iam.list_access_keys(UserName=u),
                )
                keys = (keys_resp or {}).get("AccessKeyMetadata", [])
                active_keys = [k for k in keys if k.get("Status") == "Active"]
                last_used = None
                for key in active_keys:
                    meta_resp = ctx.call(
                        "iam",
                        "aws_iam_access_key_last_used",
                        lambda k=key: iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]),
                    )
                    if meta_resp:
                        used = meta_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if used and (last_used is None or used > last_used):
                            last_used = used
                inactive_days = None
                if last_used:
                    inactive_days = (datetime.now(timezone.utc) - last_used).days
                is_orphaned = inactive_days is not None and inactive_days > 90
                if is_orphaned:
                    orphaned += 1
                policies_resp = ctx.call(
                    "iam",
                    "aws_iam_attached_policies",
                    lambda u=name: iam.list_attached_user_policies(UserName=u),
                )
                policies = (policies_resp or {}).get("AttachedPolicies", [])
                is_priv = any("Admin" in p.get("PolicyName", "") for p in policies)
                if is_priv:
                    privileged += 1
                users.append(
                    {
                        "username": name,
                        "active_keys": len(active_keys),
                        "inactive_days": inactive_days,
                        "orphaned": is_orphaned,
                        "privileged": is_priv,
                    }
                )

    days_since_review = _credential_report_days(iam, ctx)

    csv_buf = io.StringIO()
    writer = csv.DictWriter(
        csv_buf,
        fieldnames=["username", "active_keys", "inactive_days", "orphaned", "privileged"],
    )
    writer.writeheader()
    writer.writerows(users)

    return finalize_snapshot(
        {
            "users": users,
            "total_identities": len(users),
            "orphaned_accounts": orphaned,
            "privileged_count": privileged,
            "days_since_last_review": days_since_review,
            "csv": csv_buf.getvalue(),
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )