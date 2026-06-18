from __future__ import annotations

from typing import Any

from sentinel.providers._snapshot import merge_results
from sentinel.providers.aws import config as aws_config
from sentinel.providers.aws import encryption as aws_encryption
from sentinel.providers.aws import iam as aws_iam
from sentinel.providers.aws._client import AwsClients


def _pillar_level(score: float) -> str:
    if score >= 90:
        return "Optimized"
    if score >= 75:
        return "Managed"
    if score >= 50:
        return "Initial"
    return "Developing"


def zt_verification_snapshot(ctx: AwsClients) -> dict[str, Any]:
    iam = aws_iam.iam_access_snapshot(ctx)
    enc = aws_encryption.encryption_snapshot(AwsClients(region=ctx.region))
    cfg = aws_config.config_and_auth_snapshot(AwsClients(region=ctx.region))

    standing = sum(1 for u in iam.get("users", []) if u.get("privileged"))
    orphaned = iam.get("orphaned_accounts", 0)
    unencrypted = enc.get("unencrypted_cui_count", 0)
    mfa_pct = cfg.get("mfa_enforcement_percent")

    identity_score = 100.0
    if orphaned:
        identity_score -= min(orphaned * 5, 40)
    if mfa_pct is not None and mfa_pct < 100:
        identity_score -= 100 - mfa_pct

    data_score = 100.0 if unencrypted == 0 else max(0, 100 - unencrypted * 10)
    network_score = 100.0 - min(cfg.get("open_http_listeners", 0) * 5, 50)

    merged = merge_results(iam, enc, cfg)
    merged.update(
        {
            "iam_review_days_ago": iam.get("days_since_last_review"),
            "encryption_status": "green" if unencrypted == 0 else "red",
            "orphaned_accounts": orphaned,
            "unencrypted_resources": unencrypted,
            "mfa_enforcement_percent": mfa_pct,
            "jit_recommendations": [
                f"Review {standing} privileged accounts for JIT conversion"
            ]
            if standing
            else [],
            "session_timeout_compliant": mfa_pct == 100.0 if mfa_pct is not None else False,
            "privileged_standing_count": standing,
            "pillar_scores": {
                "Identity": _pillar_level(identity_score),
                "Device": _pillar_level(mfa_pct or 0),
                "Network": _pillar_level(network_score),
                "Application": _pillar_level(100 - cfg.get("weak_tls_listeners", 0) * 10),
                "Data": _pillar_level(data_score),
                "Analytics": _pillar_level(75.0),
                "Governance": _pillar_level(identity_score),
            },
        }
    )
    return merged