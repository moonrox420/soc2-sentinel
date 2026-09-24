from __future__ import annotations

from typing import Any

from sentinel.providers._snapshot import merge_results
from sentinel.providers.azure import config as azure_config
from sentinel.providers.azure import encryption as azure_encryption
from sentinel.providers.azure import iam as azure_iam
from sentinel.providers.azure._client import AzureContext


def zt_verification_snapshot(ctx: AzureContext) -> dict[str, Any]:
    iam = azure_iam.iam_access_snapshot(ctx)
    enc = azure_encryption.encryption_snapshot(AzureContext(subscription_id=ctx.subscription_id))
    cfg = azure_config.config_and_auth_snapshot(AzureContext(subscription_id=ctx.subscription_id))

    unencrypted = enc.get("unencrypted_cui_count", 0)
    mfa_pct = cfg.get("mfa_enforcement_percent")
    mfa_registered_pct = cfg.get("mfa_registered_percent")
    orphaned = iam.get("orphaned_accounts")

    merged = merge_results(iam, enc, cfg)
    merged.update(
        {
            "iam_review_days_ago": iam.get("days_since_last_review"),
            "encryption_status": "green" if unencrypted == 0 else "red",
            "orphaned_accounts": orphaned,
            "unencrypted_resources": unencrypted,
            "mfa_enforcement_percent": mfa_pct,
            "mfa_registered_percent": mfa_registered_pct,
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
                    "source_metrics": ["privileged_count", "mfa_registered_percent"],
                    "limitations": "MFA registration does not prove enforcement, and access-review timing is not collected.",
                },
                "Device": {"source_metrics": [], "limitations": "Not collected."},
                "Network": {"source_metrics": [], "limitations": "Not collected for ZT maturity."},
                "Application": {"source_metrics": [], "limitations": "Not collected for ZT maturity."},
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
