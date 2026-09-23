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
    mfa_registered_pct = cfg.get("mfa_registered_percent")

    identity_score = 100.0
    if orphaned:
        identity_score -= min(orphaned * 5, 40)
    if mfa_registered_pct is not None and mfa_registered_pct < 100:
        identity_score -= 100 - mfa_registered_pct

    data_score = 100.0 if unencrypted == 0 else max(0, 100 - unencrypted * 10)

    merged = merge_results(iam, enc, cfg)
    merged.update(
        {
            "iam_review_days_ago": iam.get("days_since_last_review"),
            "encryption_status": "green" if unencrypted == 0 else "red",
            "orphaned_accounts": orphaned,
            "unencrypted_resources": unencrypted,
            "mfa_enforcement_percent": mfa_pct,
            "mfa_registered_percent": mfa_registered_pct,
            "jit_recommendations": [
                f"Review {standing} privileged accounts for JIT conversion"
            ]
            if standing
            else [],
            "session_timeout_compliant": None,
            "privileged_standing_count": standing,
            "pillar_scores": {
                "Identity": _pillar_level(identity_score),
                "Device": "Not Assessed",
                "Network": "Not Assessed",
                "Application": "Not Assessed",
                "Data": _pillar_level(data_score),
                "Analytics": "Not Assessed",
                "Governance": "Not Assessed",
            },
            "pillar_provenance": {
                "Identity": {
                    "source_metrics": ["orphaned_accounts", "mfa_registered_percent"],
                    "limitations": "MFA registration and stale-account signals do not prove continuous access-review enforcement.",
                },
                "Device": {
                    "source_metrics": [],
                    "limitations": "No endpoint/device-posture API is collected.",
                },
                "Network": {
                    "source_metrics": ["open_http_listeners"],
                    "limitations": "HTTP listener exposure is a signal only and is not sufficient for a Zero Trust network maturity rating.",
                },
                "Application": {
                    "source_metrics": ["weak_tls_listeners"],
                    "limitations": "TLS policy observations alone are not sufficient for application-pillar maturity.",
                },
                "Data": {
                    "source_metrics": ["unencrypted_cui_count"],
                    "limitations": "Encryption posture is measured; broader data discovery/classification controls are not.",
                },
                "Analytics": {
                    "source_metrics": [],
                    "limitations": "No analytics/SIEM maturity evidence is collected by this snapshot.",
                },
                "Governance": {
                    "source_metrics": [],
                    "limitations": "No governance maturity evidence is collected by this snapshot.",
                },
            },
        }
    )
    return merged