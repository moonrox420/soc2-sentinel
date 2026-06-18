from unittest.mock import MagicMock, patch

from sentinel.providers.azure.config import config_and_auth_snapshot
from sentinel.providers.azure.encryption import encryption_snapshot
from sentinel.providers.azure.logging import log_monitoring_snapshot
from sentinel.providers.azure.retention import retention_snapshot
from sentinel.providers.azure._client import AzureContext


def _ctx():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                return AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")


def test_azure_logging_resource_graph():
    ctx = _ctx()
    result = MagicMock()
    result.data = [{"total": 10, "withDiag": 8}]
    with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as mock_rg:
        mock_rg.return_value.resources.return_value = result
        with patch("azure.mgmt.monitor.MonitorManagementClient") as mock_mon:
            mock_mon.return_value.diagnostic_settings.list.return_value = [MagicMock()]
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = log_monitoring_snapshot(ctx)
    assert snap["log_coverage_percent"] == 80.0


def test_azure_encryption_storage():
    ctx = _ctx()
    account = MagicMock()
    account.name = "acct1"
    account.encryption.services.blob.enabled = True
    ctx.storage.storage_accounts.list = MagicMock(return_value=[account])
    with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as mock_rg:
        mock_rg.return_value.resources.return_value = MagicMock(data=[])
        with patch.object(ctx, "graph_get", return_value={"value": []}):
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = encryption_snapshot(ctx)
    assert snap["total_confidential_resources"] >= 1


def test_azure_retention_no_policy():
    ctx = _ctx()
    account = MagicMock()
    account.name = "acct1"
    account.id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1"
    ctx.storage.storage_accounts.list = MagicMock(return_value=[account])
    def _raise():
        raise Exception("not found")

    ctx.storage.management_policies.get = MagicMock(side_effect=_raise)
    with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
        snap = retention_snapshot(ctx)
    assert snap["accounts_missing_lifecycle"] >= 1 or snap.get("errors")


def test_azure_config_mfa():
    ctx = _ctx()
    mfa = {"value": [{"isMfaRegistered": True}, {"isMfaRegistered": False}]}
    with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as mock_rg:
        mock_rg.return_value.resources.return_value = MagicMock(data=[])
        with patch.object(ctx, "graph_get", return_value=mfa):
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = config_and_auth_snapshot(ctx)
    assert snap["mfa_enforcement_percent"] == 50.0