import os


from sentinel.security import (
    decrypt_bytes,
    encryption_enabled,
    encryption_header_version,
    hmac_sign,
)


def test_v1_decrypt_legacy(monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "legacy-key")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hashlib

    key = hashlib.sha256(b"sentinel-evidence-v1:legacy-key").digest()
    nonce = os.urandom(12)
    blob = b"SSENC1" + nonce + AESGCM(key).encrypt(nonce, b"old-data", None)
    assert decrypt_bytes(blob) == b"old-data"
    assert encryption_header_version(blob) == "v1"


def test_encryption_enabled_from_file(tmp_path, monkeypatch):
    key_file = tmp_path / "key.txt"
    key_file.write_text("file-secret", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY_FILE", str(key_file))
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    enabled, secret = encryption_enabled(config_flag=True)
    assert enabled
    assert secret == "file-secret"


def test_hmac_sign_deterministic():
    assert hmac_sign(b"payload", secret="s") == hmac_sign(b"payload", secret="s")