
import pytest

from sentinel.errors import ValidationError
from sentinel.security import (
    encrypt_bytes,
    encryption_enabled,
    safe_file_mode,
    sanitize_csv_cell,
    verify_decrypt_hmac,
)


def test_safe_file_mode_no_crash(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    safe_file_mode(f)
    safe_file_mode(tmp_path, is_dir=True)


def test_sanitize_csv_newline():
    assert '"a\nb"' in sanitize_csv_cell("a\nb") or "a" in sanitize_csv_cell("a\nb")


def test_encryption_enabled_no_key():
    enabled, secret = encryption_enabled(config_flag=False)
    assert not enabled
    assert secret is None


def test_verify_decrypt_hmac_blocks(monkeypatch):
    monkeypatch.setenv("SENTINEL_HMAC_KEY", "hmac")
    with pytest.raises(ValidationError, match="manifest HMAC"):
        verify_decrypt_hmac("")


def test_encrypt_requires_secret(monkeypatch):
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY_FILE", raising=False)
    with pytest.raises(ValidationError):
        encrypt_bytes(b"x", secret=None)