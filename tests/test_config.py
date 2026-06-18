
import pytest

from sentinel.config import load_config
from sentinel.errors import ValidationError


def test_load_config_defaults():
    cfg = load_config(None)
    assert cfg.evidence.encrypt is False
    assert cfg.validation.strict_allowlist is True


def test_validate_encrypt_requires_key(monkeypatch):
    from sentinel.config import SentinelConfig, EvidenceConfig

    cfg = SentinelConfig(evidence=EvidenceConfig(encrypt=True))
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY_FILE", raising=False)
    with pytest.raises(ValidationError, match="SENTINEL_EVIDENCE_KEY"):
        cfg.validate()


def test_validate_threshold_order():
    from sentinel.config import SentinelConfig, ThresholdConfig

    cfg = SentinelConfig(thresholds=ThresholdConfig(orphaned_accounts_yellow=10, orphaned_accounts_red=5))
    with pytest.raises(ValidationError, match="yellow"):
        cfg.validate()


def test_load_config_from_yaml(tmp_path):
    yaml_path = tmp_path / "sentinel.yaml"
    yaml_path.write_text(
        "evidence:\n  encrypt: false\nvalidation:\n  strict_allowlist: false\n",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.validation.strict_allowlist is False


def test_validate_bad_threshold_int(tmp_path):
    yaml_path = tmp_path / "sentinel.yaml"
    yaml_path.write_text("thresholds:\n  orphaned_accounts_red: not-a-number\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="integer"):
        load_config(yaml_path)