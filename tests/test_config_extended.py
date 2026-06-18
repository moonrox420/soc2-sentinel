import os
import stat

import pytest

from sentinel.config import EvidenceConfig, SentinelConfig, load_config
from sentinel.errors import ValidationError


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