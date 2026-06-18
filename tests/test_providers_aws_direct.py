from unittest.mock import patch

from sentinel.providers.aws.provider import AwsProvider
from sentinel.providers.aws._client import AwsClients


def test_aws_validate_credentials():
    with patch.object(AwsClients, "validate_credentials") as mock:
        p = AwsProvider(region="us-east-1")
        p.validate_credentials()
        mock.assert_called_once()


def test_aws_all_snapshot_methods():
    p = AwsProvider(region="us-east-1")
    stub = {"collection_quality": "complete", "errors": [], "partial": False}
    patches = {
        "iam_access_snapshot": "sentinel.providers.aws.provider.aws_iam.iam_access_snapshot",
        "log_monitoring_snapshot": "sentinel.providers.aws.provider.aws_logging.log_monitoring_snapshot",
        "config_and_auth_snapshot": "sentinel.providers.aws.provider.aws_config.config_and_auth_snapshot",
        "encryption_snapshot": "sentinel.providers.aws.provider.aws_encryption.encryption_snapshot",
        "retention_snapshot": "sentinel.providers.aws.provider.aws_retention.retention_snapshot",
        "resilience_snapshot": "sentinel.providers.aws.provider.aws_resilience.resilience_snapshot",
        "zt_verification_snapshot": "sentinel.providers.aws.provider.aws_zt",
    }
    for attr, target in patches.items():
        with patch(target, return_value=stub):
            assert getattr(p, attr)()["collection_quality"] == "complete"