from __future__ import annotations

import csv
import io
import logging
from typing import Any

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.iam")

_PRIVILEGED_ROLES = frozenset(
    {"Global Administrator", "Privileged Role Administrator", "Security Administrator", "Owner"}
)


def iam_access_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure IAM access snapshot")
    users: list[dict[str, Any]] = []
    privileged = 0
    orphaned = 0

    roles_data = ctx.graph_get("/directoryRoles")
    if roles_data:
        for role in roles_data.get("value", []):
            role_name = role.get("displayName", "")
            members = ctx.graph_get(f"/directoryRoles/{role['id']}/members")
            if not members:
                continue
            is_priv = role_name in _PRIVILEGED_ROLES
            for member in members.get("value", []):
                if is_priv:
                    privileged += 1
                users.append(
                    {
                        "username": member.get("userPrincipalName", member.get("id", "unknown")),
                        "role": role_name,
                        "orphaned": False,
                        "privileged": is_priv,
                    }
                )

    signins = ctx.graph_get("/users?$select=id,userPrincipalName,signInActivity&$top=50")
    if signins:
        for user in signins.get("value", []):
            activity = user.get("signInActivity") or {}
            last = activity.get("lastSignInDateTime")
            if not last:
                orphaned += 1
                users.append(
                    {
                        "username": user.get("userPrincipalName", user.get("id")),
                        "role": "user",
                        "orphaned": True,
                        "privileged": False,
                    }
                )

    csv_buf = io.StringIO()
    if users:
        writer = csv.DictWriter(
            csv_buf, fieldnames=["username", "role", "orphaned", "privileged"], extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(users)

    return finalize_snapshot(
        {
            "users": users,
            "total_identities": len(users),
            "orphaned_accounts": orphaned,
            "privileged_count": privileged,
            "days_since_last_review": None,
            "csv": csv_buf.getvalue() or "principal,role,scope\n",
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )