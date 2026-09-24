import pytest

from sentinel.config import load_config
from sentinel.errors import ValidationError


def test_load_config_defaults():
    cfg = load_config(None)
    assert cfg.evidence.encrypt is False
    assert cfg.validation.strict_allowlist is True


def test_validate_encrypt_requires_key(monkeypatch):
    from sentinel.config import EvidenceConfig, SentinelConfig

    cfg = SentinelConfig(evidence=EvidenceConfig(encrypt=True))
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY_FILE", raising=False)
    with pytest.raises(ValidationError, match="SENTINEL_EVIDENCE_KEY"):
        cfg.validate()


def test_validate_threshold_order():
    from sentinel.config import SentinelConfig, ThresholdConfig

    cfg = SentinelConfig(
        thresholds=ThresholdConfig(orphaned_accounts_yellow=10, orphaned_accounts_red=5)
    )
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
    yaml_path.write_text(
        "thresholds:\n  orphaned_accounts_red: not-a-number\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError, match="integer"):
        load_config(yaml_path)


# --- Consolidated from test_config_extended.py ---
import os
import stat

from sentinel.config import EvidenceConfig, SentinelConfig


def test_validate_key_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY_FILE", str(tmp_path / "missing.key"))
    cfg = SentinelConfig(evidence=EvidenceConfig(encrypt=True))
    with pytest.raises(ValidationError, match="SENTINEL_EVIDENCE_KEY_FILE"):
        cfg.validate()


def test_validate_yaml_permissions_warning(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("unix permission test")
    yaml_path = tmp_path / "sentinel.yaml"
    yaml_path.write_text("evidence:\n  encrypt: false\n", encoding="utf-8")
    yaml_path.chmod(stat.S_IROTH | stat.S_IRUSR | stat.S_IWUSR)
    cfg = load_config(yaml_path)
    warnings = cfg.validate()
    assert any("world-readable" in w for w in warnings)


# --- Consolidated from test_logging_config_direct.py ---
from sentinel.logging_config import configure_logging


def test_configure_logging_verbose_and_file(tmp_path):
    log_path = tmp_path / "sentinel.log"
    logger = configure_logging(verbose=True, log_file=log_path)
    logger.info("test message", extra={"collector": "iam_access_review"})
    assert log_path.exists()
    assert "test message" in log_path.read_text(encoding="utf-8")
