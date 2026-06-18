from unittest.mock import patch

from moto import mock_aws

from sentinel.providers.aws._zt import zt_verification_snapshot
from sentinel.providers.aws._client import AwsClients


@mock_aws
def test_zt_derives_pillar_scores():
    ctx = AwsClients(region="us-east-1")
    with patch("sentinel.providers.aws.iam.iam_access_snapshot") as mock_iam:
        with patch("sentinel.providers.aws.encryption.encryption_snapshot") as mock_enc:
            with patch("sentinel.providers.aws.config.config_and_auth_snapshot") as mock_cfg:
                mock_iam.return_value = {
                    "users": [{"privileged": True}],
                    "orphaned_accounts": 0,
                    "days_since_last_review": 10,
                    "errors": [],
                    "collection_quality": "complete",
                }
                mock_enc.return_value = {
                    "unencrypted_cui_count": 0,
                    "errors": [],
                    "collection_quality": "complete",
                }
                mock_cfg.return_value = {
                    "mfa_enforcement_percent": 100.0,
                    "open_http_listeners": 0,
                    "weak_tls_listeners": 0,
                    "errors": [],
                    "collection_quality": "complete",
                }
                snap = zt_verification_snapshot(ctx)
    assert "pillar_scores" in snap
    assert snap["encryption_status"] == "green"