from __future__ import annotations

from typing import Any

from sentinel.providers._snapshot import merge_results
from sentinel.providers.gcp import config as gcp_config
from sentinel.providers.gcp import encryption as gcp_encryption
from sentinel.providers.gcp import iam as gcp_iam
from sentinel.providers.gcp._client import GcpContext


def zt_verification_snapshot(ctx: GcpContext) -> dict[str, Any]:
    iam = gcp_iam.iam_access_snapshot(ctx)
    enc = gcp_encryption.encryption_snapshot(GcpContext(project_id=ctx.project_id))
    cfg = gcp_config.config_and_auth_snapshot(GcpContext(project_id=ctx.project_id))

    unencrypted = enc.get("unencrypted_cui_count", 0)
    mfa_pct = cfg.get("mfa_enforcement_percent")
    orphaned = iam.get("orphaned_accounts")

    merged = merge_results(iam, enc, cfg)
    merged.update(
        {
            "iam_review_days_ago": iam.get("days_since_last_review"),
            "encryption_status": "green" if unencrypted == 0 else "red",
            "orphaned_accounts": orphaned,
            "unencrypted_resources": unencrypted,
            "mfa_enforcement_percent": mfa_pct,
            "jit_recommendations": [],
            "session_timeout_compliant": None,
            "privileged_standing_count": iam.get("privileged_count", 0),
            "pillar_scores": {
                "Identity": "Not Assessed",
                "Device": "Not Assessed",
                "Network": "Not Assessed",
                "Application": "Not Assessed",
                "Data": "Managed" if unencrypted == 0 else "Developing",
                "Analytics": "Not Assessed",
                "Governance": "Not Assessed",
            },
            "pillar_provenance": {
                "Identity": {
                    "source_metrics": [
                        "privileged_count",
                        "stale_service_account_keys",
                    ],
                    "limitations": "No reliable account-inactivity, access-review-date, or MFA-enforcement metric is collected.",
                },
                "Device": {"source_metrics": [], "limitations": "Not collected."},
                "Network": {
                    "source_metrics": [],
                    "limitations": "Not collected for ZT maturity.",
                },
                "Application": {
                    "source_metrics": [],
                    "limitations": "Not collected for ZT maturity.",
                },
                "Data": {
                    "source_metrics": ["unencrypted_cui_count"],
                    "limitations": "Encryption posture is measured; broader data controls are not.",
                },
                "Analytics": {"source_metrics": [], "limitations": "Not collected."},
                "Governance": {"source_metrics": [], "limitations": "Not collected."},
            },
        }
    )
    return merged
