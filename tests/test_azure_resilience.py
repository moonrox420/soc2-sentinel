from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sentinel.providers.azure.resilience import resilience_snapshot
from sentinel.providers.azure._client import AzureContext


def test_recovery_services_jobs():
    ctx = AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")
    mock_vault = MagicMock()
    mock_vault.name = "vault1"
    mock_vault.id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/vault1"
    mock_job = MagicMock()
    mock_job.properties.status = "Completed"
    mock_job.properties.end_time = datetime.now(timezone.utc)
    with patch("azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient") as mock_cls:
        inst = mock_cls.return_value
        inst.backup_vaults.list_in_subscription.return_value = [mock_vault]
        inst.backup_jobs.list.return_value = [mock_job]
        inst.backup_protected_items.list.return_value = []
        snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None
    assert snap["backup_jobs_success_30d"] >= 1