from unittest.mock import MagicMock, patch

from sentinel.providers.aws.logging import log_monitoring_snapshot
from sentinel.providers.aws._client import AwsClients


def test_no_trails_sets_coverage_error():
    ctx = AwsClients(region="us-east-1")
    with patch.object(ctx, "client") as mock_client:
        trails = MagicMock()
        trails.describe_trails.return_value = {"trailList": []}
        mock_client.return_value = trails
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = log_monitoring_snapshot(ctx)
    assert snap.get("log_coverage_percent") is None
    assert any(e.get("code") == "NoTrails" for e in snap.get("errors", []))


def test_trail_logging_coverage():
    ctx = AwsClients(region="us-east-1")
    trail = {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/t1", "Name": "t1", "IsMultiRegionTrail": True}
    with patch.object(ctx, "client") as mock_client:
        trails = MagicMock()
        trails.describe_trails.return_value = {"trailList": [trail]}
        trails.get_trail_status.return_value = {
            "IsLogging": True,
            "LatestDeliveryTime": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        }
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        logs = MagicMock()
        logs.describe_log_groups.return_value = {"logGroups": [{"retentionInDays": 30}]}
        trails.lookup_events.return_value = {"Events": []}

        def client_factory(svc):
            return {"cloudtrail": trails, "config": cfg, "logs": logs}[svc]

        mock_client.side_effect = client_factory
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = log_monitoring_snapshot(ctx)
    assert snap.get("log_coverage_percent") == 100.0