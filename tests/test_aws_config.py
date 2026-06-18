from unittest.mock import MagicMock, patch

from sentinel.providers.aws.config import config_and_auth_snapshot
from sentinel.providers.aws._client import AwsClients


def test_mfa_counts_from_users():
    ctx = AwsClients(region="us-east-1")
    user_page = {"Users": [{"UserName": "alice"}]}
    with patch.object(ctx, "client") as mock_client:
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [user_page]
        iam.list_mfa_devices.return_value = {"MFADevices": []}
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.return_value = []
        elbv2 = MagicMock()
        elbv2.get_paginator.return_value.paginate.return_value = []
        cfg = MagicMock()
        cfg.describe_config_rules.return_value = {"ConfigRules": []}
        cfg.get_compliance_summary_by_config_rule.return_value = {"ComplianceSummaries": []}
        mock_client.side_effect = lambda s: {"iam": iam, "ec2": ec2, "elbv2": elbv2, "config": cfg}[s]
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = config_and_auth_snapshot(ctx)
    assert snap["weak_auth_methods"] >= 1
    assert snap["mfa_enforcement_percent"] < 100.0