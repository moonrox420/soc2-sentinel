import json

from sentinel.collectors.resilience_testing import collect_resilience_testing
from sentinel.config import SentinelConfig
from sentinel.providers.base import Provider


class PartialResilienceProvider(Provider):
    name = "mock"

    def validate_credentials(self) -> None:
        pass

    def resilience_snapshot(self):
        return {
            "last_backup_hours_ago": 12,
            "last_restore_test_days_ago": 120,
            "failover_test_passed": False,
            "backup_jobs_failed_30d": 2,
            "errors": [{"code": "Partial", "message": "x", "severity": "medium"}],
            "collection_quality": "partial",
            "partial": True,
        }

    def iam_access_snapshot(self):
        raise NotImplementedError

    def log_monitoring_snapshot(self):
        raise NotImplementedError

    def config_and_auth_snapshot(self):
        raise NotImplementedError

    def encryption_snapshot(self):
        raise NotImplementedError

    def retention_snapshot(self):
        raise NotImplementedError

    def zt_verification_snapshot(self):
        raise NotImplementedError


def test_resilience_collector_partial(tmp_path):
    path = collect_resilience_testing(PartialResilienceProvider(), base=tmp_path, config=SentinelConfig())
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["collection_quality"] == "partial"
    assert payload["status"] in {"yellow", "red"}