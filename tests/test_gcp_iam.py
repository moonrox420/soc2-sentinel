from unittest.mock import MagicMock, patch

from sentinel.providers.gcp.iam import iam_access_snapshot
from sentinel.providers.gcp._client import GcpContext


def test_asset_api_drives_user_counts():
    ctx = GcpContext(project_id="test-project")
    mock_policy = MagicMock()
    mock_policy.policy.bindings = [
        MagicMock(role="roles/owner", members=["user:admin@test.com"]),
    ]
    with patch("google.cloud.asset_v1.AssetServiceClient") as mock_client:
        mock_client.return_value.search_all_iam_policies.return_value = [mock_policy]
        with patch("google.cloud.iam_admin_v1.IAMClient") as mock_iam:
            mock_iam.return_value.list_service_accounts.return_value = []
            snap = iam_access_snapshot(ctx)
    assert snap["total_identities"] >= 1
    assert snap["privileged_count"] >= 1