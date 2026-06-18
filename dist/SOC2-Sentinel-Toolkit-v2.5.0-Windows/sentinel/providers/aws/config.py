from __future__ import annotations

import logging
from typing import Any

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.config")


def config_and_auth_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS config/auth snapshot")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cfg = ctx.client("config")

    mfa_enforced = 0
    total_users = 0
    weak_auth = 0
    open_http = 0
    weak_tls = 0
    unapproved = 0
    missing_rollback = 0

    pages = ctx.call("iam", "aws_iam_list_users", lambda: list(iam.get_paginator("list_users").paginate()))
    if pages:
        for page in pages:
            for user in page.get("Users", []):
                total_users += 1
                devices_resp = ctx.call(
                    "iam",
                    "aws_iam_mfa_devices",
                    lambda u=user: iam.list_mfa_devices(UserName=u["UserName"]),
                )
                devices = (devices_resp or {}).get("MFADevices", [])
                if devices:
                    mfa_enforced += 1
                else:
                    weak_auth += 1

    sg_pages = ctx.call(
        "ec2",
        "aws_ec2_security_groups",
        lambda: list(ec2.get_paginator("describe_security_groups").paginate()),
    )
    if sg_pages:
        for page in sg_pages:
            for sg in page.get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    if perm.get("FromPort") == 80:
                        open_http += 1

    lb_pages = ctx.call(
        "elbv2",
        "aws_elb_list",
        lambda: list(elbv2.get_paginator("describe_load_balancers").paginate()),
    )
    if lb_pages:
        for lb_page in lb_pages:
            for lb in lb_page.get("LoadBalancers", []):
                listeners_resp = ctx.call(
                    "elbv2",
                    "aws_elb_listeners",
                    lambda a=lb: elbv2.describe_listeners(LoadBalancerArn=a["LoadBalancerArn"]),
                )
                if listeners_resp:
                    for listener in listeners_resp.get("Listeners", []):
                        ssl = listener.get("SslPolicy", "")
                        if ssl and "2016" in ssl:
                            weak_tls += 1

    rules_resp = ctx.call(
        "config",
        "aws_config_rules",
        lambda: cfg.describe_config_rules(),
    )
    if rules_resp:
        for rule in rules_resp.get("ConfigRules", []):
            name = rule.get("ConfigRuleName", "")
            if "change" in name.lower() or "approved" in name.lower():
                detail_resp = ctx.call(
                    "config",
                    "aws_config_compliance",
                    lambda n=name: cfg.get_compliance_details_by_config_rule(ConfigRuleName=n),
                )
                if detail_resp:
                    for result in detail_resp.get("EvaluationResults", []):
                        compliance = result.get("ComplianceType", "")
                        if compliance == "NON_COMPLIANT":
                            unapproved += 1

    summary_resp = ctx.call(
        "config",
        "aws_config_compliance_summary",
        lambda: cfg.get_compliance_summary_by_config_rule(),
    )
    if summary_resp:
        for summary in summary_resp.get("ComplianceSummaries", []):
            if summary.get("ComplianceSummary", {}).get("NonCompliantResourceCount", {}).get(
                "CappedCount", 0
            ):
                missing_rollback += summary["ComplianceSummary"]["NonCompliantResourceCount"][
                    "CappedCount"
                ]

    mfa_pct = round((mfa_enforced / total_users) * 100, 1) if total_users else None

    return finalize_snapshot(
        {
            "mfa_enforcement_percent": mfa_pct if mfa_pct is not None else 0.0,
            "weak_auth_methods": weak_auth,
            "open_http_listeners": open_http,
            "weak_tls_listeners": weak_tls,
            "unapproved_changes": unapproved,
            "changes_missing_rollback_test": missing_rollback,
            "issues": open_http + weak_tls + unapproved,
            "warnings": 0 if mfa_pct == 100.0 else 1,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )