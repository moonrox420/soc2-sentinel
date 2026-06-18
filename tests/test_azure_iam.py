from unittest.mock import patch

from sentinel.providers.azure.iam import iam_access_snapshot
from sentinel.providers.azure._client import AzureContext


def test_graph_drives_assignments():
    ctx = AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")
    roles = {"value": [{"id": "role-1", "displayName": "Global Administrator"}]}
    members = {"value": [{"userPrincipalName": "admin@contoso.com", "id": "u1"}]}
    with patch.object(ctx, "graph_get", side_effect=[roles, members, None]):
        snap = iam_access_snapshot(ctx)
    assert snap["privileged_count"] >= 1
    assert snap["total_identities"] >= 1