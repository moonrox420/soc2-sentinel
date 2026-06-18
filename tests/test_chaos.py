

from sentinel.collectors.iam_access_review import collect_iam_access_review
from sentinel.config import SentinelConfig
from sentinel.providers.base import Provider


class ChaosProvider(Provider):
    name = "mock"

    def validate_credentials(self) -> None:
        pass

    def iam_access_snapshot(self):
        return {
            "users": [],
            "total_identities": 0,
            "orphaned_accounts": 0,
            "privileged_count": 0,
            "errors": [{"code": "Timeout", "message": "API timeout", "severity": "high"}],
            "collection_quality": "partial",
            "partial": True,
            "csv": "",
        }

    def log_monitoring_snapshot(self):
        raise NotImplementedError

    def config_and_auth_snapshot(self):
        raise NotImplementedError

    def encryption_snapshot(self):
        raise NotImplementedError

    def retention_snapshot(self):
        raise NotImplementedError

    def resilience_snapshot(self):
        raise NotImplementedError

    def zt_verification_snapshot(self):
        raise NotImplementedError


def test_partial_collection_yellow_status(tmp_path):
    path = collect_iam_access_review(ChaosProvider(), base=tmp_path, config=SentinelConfig())
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["collection_quality"] == "partial"
    assert payload["status"] == "yellow"
    assert len(payload["errors"]) == 1