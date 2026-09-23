from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sentinel.providers.azure._client import AzureContext
from sentinel.providers.azure.resilience import resilience_snapshot


def _completed_backup_job():
    job = MagicMock()
    job.properties.status = "Completed"
    job.properties.operation = "Backup"
    job.properties.end_time = datetime.now(timezone.utc)
    return job


def test_recovery_services_backup_jobs():
    ctx = AzureContext(
        subscription_id="00000000-0000-0000-0000-000000000001"
    )
    mock_vault = MagicMock()
    mock_vault.name = "vault1"
    mock_vault.id = (
        "/subscriptions/sub/resourceGroups/rg/providers/"
        "Microsoft.RecoveryServices/vaults/vault1"
    )

    with patch(
        "azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient"
    ) as mock_cls:
        inst = mock_cls.return_value
        inst.backup_vaults.list_in_subscription.return_value = [mock_vault]
        inst.backup_jobs.list.return_value = [_completed_backup_job()]
        inst.backup_protected_items.list.return_value = []
        snap = resilience_snapshot(ctx)

    assert snap["last_backup_hours_ago"] is not None
    assert snap["backup_jobs_success_30d"] >= 1


def test_backup_success_does_not_imply_restore_or_failover():
    ctx = AzureContext(
        subscription_id="00000000-0000-0000-0000-000000000001"
    )
    mock_vault = MagicMock()
    mock_vault.name = "vault1"
    mock_vault.id = (
        "/subscriptions/sub/resourceGroups/rg/providers/"
        "Microsoft.RecoveryServices/vaults/vault1"
    )

    with patch(
        "azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient"
    ) as mock_cls:
        inst = mock_cls.return_value
        inst.backup_vaults.list_in_subscription.return_value = [mock_vault]
        inst.backup_jobs.list.return_value = [_completed_backup_job()]
        inst.backup_protected_items.list.return_value = []
        snap = resilience_snapshot(ctx)

    assert snap["last_restore_test_days_ago"] is None
    assert snap["failover_test_days_ago"] is None
    assert snap["failover_test_passed"] is None
    assert snap["collection_quality"] == "partial"
    assert any(
        error["code"] == "FailoverTestNotCollected"
        for error in snap["errors"]
    )
