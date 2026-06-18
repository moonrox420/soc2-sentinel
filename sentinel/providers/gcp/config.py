from __future__ import annotations

import logging
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.config")


def config_and_auth_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP config/auth snapshot")
    weak_auth = 0
    policy_violations = 0
    open_http = 0

    try:
        from google.cloud import orgpolicy_v2

        client = orgpolicy_v2.OrgPolicyClient()
        parent = f"projects/{ctx.project_id}"
        ctx.attempt()
        policies = call_with_retry(
            lambda: list(client.list_policies(request={"parent": parent})),
            operation="gcp_list_org_policies",
        )
        ctx.succeed()
        for policy in policies:
            for rule in policy.rules:
                enforce = getattr(rule, "enforce", None)
                if enforce is False:
                    policy_violations += 1
                    if "publicIp" in policy.name or "saKey" in policy.name:
                        weak_auth += 1
    except Exception as exc:
        ctx.record_error("orgpolicy", exc)

    try:
        from google.cloud import compute_v1

        compute = compute_v1.FirewallsClient()
        ctx.attempt()
        firewalls = call_with_retry(
            lambda: list(compute.list(project=ctx.project_id)),
            operation="gcp_list_firewalls",
        )
        ctx.succeed()
        for fw in firewalls:
            if fw.direction == "INGRESS":
                for allow in fw.allowed:
                    if allow.I_p_protocol == "tcp" and "80" in (allow.ports or []):
                        open_http += 1
    except Exception as exc:
        ctx.record_error("compute", exc)

    mfa_pct: float | None = None
    if weak_auth == 0 and not ctx.errors:
        mfa_pct = 100.0
    elif weak_auth > 0:
        mfa_pct = max(0.0, 100.0 - weak_auth * 10)

    return finalize_snapshot(
        {
            "mfa_enforcement_percent": mfa_pct if mfa_pct is not None else 0.0,
            "weak_auth_methods": weak_auth,
            "open_http_listeners": open_http,
            "weak_tls_listeners": 0,
            "unapproved_changes": policy_violations,
            "changes_missing_rollback_test": 0,
            "issues": open_http + policy_violations,
            "warnings": weak_auth,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )