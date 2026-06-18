from unittest.mock import patch

from sentinel.providers.azure._zt import zt_verification_snapshot


def test_azure_zt_merge():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                from sentinel.providers.azure._client import AzureContext

                ctx = AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")
    with patch("sentinel.providers.azure.iam.iam_access_snapshot") as mock_iam:
        with patch("sentinel.providers.azure.encryption.encryption_snapshot") as mock_enc:
            with patch("sentinel.providers.azure.config.config_and_auth_snapshot") as mock_cfg:
                mock_iam.return_value = {"orphaned_accounts": 0, "privileged_count": 1, "errors": [], "collection_quality": "complete"}
                mock_enc.return_value = {"unencrypted_cui_count": 1, "errors": [], "collection_quality": "complete"}
                mock_cfg.return_value = {"mfa_enforcement_percent": 80.0, "errors": [], "collection_quality": "partial"}
                snap = zt_verification_snapshot(ctx)
    assert snap["encryption_status"] == "red"