from unittest.mock import MagicMock, patch

from moto import mock_aws

from sentinel.providers.aws.resilience import resilience_snapshot
from sentinel.providers.aws._client import AwsClients


def test_no_backup_jobs_returns_failed_quality():
    ctx = AwsClients(region="us-east-1")
    with patch.object(ctx, "client") as mock_client:
        backup = MagicMock()
        backup.list_backup_jobs.return_value = {"BackupJobs": []}
        backup.list_restore_jobs.return_value = {"RestoreJobs": []}
        rds = MagicMock()
        rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
        mock_client.side_effect = lambda s: {"backup": backup, "rds": rds}[s]
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is None
    assert any(e.get("code") == "NoBackupEvidence" for e in snap.get("errors", []))


@mock_aws
def test_rds_snapshot_drives_backup_hours():
    import boto3

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="db-1",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
    )
    rds.create_db_snapshot(DBSnapshotIdentifier="snap-1", DBInstanceIdentifier="db-1")
    ctx = AwsClients(region="us-east-1")
    with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
        snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None