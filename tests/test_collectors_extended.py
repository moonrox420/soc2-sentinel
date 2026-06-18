import json

from sentinel.collectors import COLLECTORS
from sentinel.config import SentinelConfig
from sentinel.providers.mock import MockProvider


def test_all_collectors_have_collection_quality(tmp_path):
    provider = MockProvider()
    defaults = {
        "iam_access_review": "CC6.1",
        "log_aggregator": "CC7.1",
        "config_drift": "CC6.2",
        "encryption_status": "C1.2",
        "retention_check": "C1.4",
        "resilience_testing": "A1.2",
        "zt_continuous_verification": "ZT-1",
    }
    cfg = SentinelConfig()
    cfg.validation.strict_allowlist = True
    for name, fn in COLLECTORS.items():
        path = fn(provider, control_id=defaults[name], base=tmp_path, config=cfg)
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "collection_quality" in payload
        assert "errors" in payload
        assert (tmp_path / "evidence").exists()
        manifest_backup = list((tmp_path / "evidence").rglob("manifests/*.json"))
        assert manifest_backup