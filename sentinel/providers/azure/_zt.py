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
    mfa_pct = cfg.get("mfa_enforcement_percent", 0)

    merged = merge_results(iam, enc, cfg)
    merged.update(
        {
            "iam_review_days_ago": iam.get("days_since_last_review"),
            "encryption_status": "green" if unencrypted == 0 else "red",
            "orphaned_accounts": iam.get("orphaned_accounts", 0),
            "unencrypted_resources": unencrypted,
            "mfa_enforcement_percent": mfa_pct,
            "jit_recommendations": [],
            "session_timeout_compliant": mfa_pct == 100.0,
            "privileged_standing_count": iam.get("privileged_count", 0),
            "pillar_scores": {
                "Identity": "Managed" if iam.get("orphaned_accounts", 0) == 0 else "Initial",
                "Data": "Managed" if unencrypted == 0 else "Developing",
            },
        }
    )
    return merged