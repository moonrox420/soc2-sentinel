from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.iam")


def iam_access_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP IAM access snapshot")
    users: list[dict[str, Any]] = []
    principals: set[str] = set()
    orphaned = 0
    privileged = 0

    try:
        from google.cloud import asset_v1

        client = asset_v1.AssetServiceClient()
        scope = f"projects/{ctx.project_id}"
        ctx.attempt()
        policies = call_with_retry(
            lambda: list(
                client.search_all_iam_policies(
                    request={"scope": scope, "page_size": 100}
                )
            ),
            operation="gcp_search_iam_policies",
        )
        ctx.succeed()
        for policy in policies:
            for binding in policy.policy.bindings:
                role = binding.role
                is_priv = "admin" in role.lower() or "owner" in role.lower()
                for member in binding.members:
                    principals.add(member)
                    if is_priv:
                        privileged += 1
                    users.append(
                        {
                            "username": member,
                            "role": role,
                            "orphaned": False,
                            "privileged": is_priv,
                        }
                    )
    except Exception as exc:
        ctx.record_error("cloudasset", exc)

    try:
        from google.cloud import iam_admin_v1

        iam = iam_admin_v1.IAMClient()
        parent = f"projects/{ctx.project_id}"
        ctx.attempt()
        accounts = call_with_retry(
            lambda: list(iam.list_service_accounts(request={"name": parent})),
            operation="gcp_list_service_accounts",
        )
        ctx.succeed()
        for sa in accounts:
            ctx.attempt()
            keys = call_with_retry(
                lambda s=sa: list(
                    iam.list_service_account_keys(
                        request={"name": s.name, "key_types": [iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]}
                    )
                ),
                operation="gcp_list_sa_keys",
            )
            ctx.succeed()
            for key in keys:
                valid = key.valid_after_time
                if valid:
                    age = (datetime.now(timezone.utc) - valid.replace(tzinfo=timezone.utc)).days
                    if age > 90:
                        orphaned += 1
                        users.append(
                            {
                                "username": sa.email,
                                "role": "serviceAccountKey",
                                "orphaned": True,
                                "privileged": False,
                                "inactive_days": age,
                            }
                        )
    except Exception as exc:
        ctx.record_error("iam", exc)

    csv_buf = io.StringIO()
    if users:
        writer = csv.DictWriter(
            csv_buf,
            fieldnames=["username", "role", "orphaned", "privileged", "inactive_days"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(users)

    return finalize_snapshot(
        {
            "users": users,
            "total_identities": len(principals) or len(users),
            "orphaned_accounts": orphaned,
            "privileged_count": privileged,
            "days_since_last_review": None,
            "csv": csv_buf.getvalue() or "principal,role,binding\n",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )