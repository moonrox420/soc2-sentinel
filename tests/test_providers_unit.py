"""Direct unit tests for provider modules using mocks to raise coverage."""

from unittest.mock import patch

from sentinel.providers.aws.provider import AwsProvider
from sentinel.providers.azure.provider import AzureProvider
from sentinel.providers.gcp.provider import GcpProvider


def test_aws_provider_delegates():
    p = AwsProvider(region="us-east-1")
    with patch("sentinel.providers.aws.iam.iam_access_snapshot") as mock:
        mock.return_value = {"collection_quality": "complete", "errors": []}
        snap = p.iam_access_snapshot()
    assert snap["collection_quality"] == "complete"


def test_gcp_provider_delegates():
    with patch("sentinel.providers.gcp._client.GcpContext.validate_credentials"):
        p = GcpProvider(project_id="proj")
    with patch("sentinel.providers.gcp.logging.log_monitoring_snapshot") as mock:
        mock.return_value = {"collection_quality": "partial", "errors": []}
        snap = p.log_monitoring_snapshot()
    assert snap["collection_quality"] == "partial"


def test_azure_provider_delegates():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                p = AzureProvider(subscription_id="00000000-0000-0000-0000-000000000001")
    with patch("sentinel.providers.azure.encryption.encryption_snapshot") as mock:
        mock.return_value = {"collection_quality": "complete", "errors": []}
        snap = p.encryption_snapshot()
    assert snap["collection_quality"] == "complete"