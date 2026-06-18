from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sentinel.providers.gcp.resilience import resilience_snapshot
from sentinel.providers.gcp._client import GcpContext


def test_compute_snapshot_timestamp():
    ctx = GcpContext(project_id="test-project")
    mock_snap = MagicMock()
    mock_snap.creation_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
    with patch("google.cloud.compute_v1.SnapshotsClient") as mock_compute:
        mock_compute.return_value.list.return_value = [mock_snap]
        with patch("googleapiclient.discovery.build") as mock_build:
            mock_build.return_value.instances.return_value.list.return_value.execute.return_value = {"items": []}
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None
    assert snap["backup_jobs_success_30d"] >= 1