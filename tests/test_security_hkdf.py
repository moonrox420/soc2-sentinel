import pytest

from sentinel.security import decrypt_bytes, encrypt_bytes, encryption_header_version


def test_hkdf_roundtrip(monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "super-secret-key-material")
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY_ID", "key-2026-01")
    plain = b"evidence payload"
    blob = encrypt_bytes(plain)
    assert encryption_header_version(blob) == "v2"
    assert decrypt_bytes(blob) == plain


def test_wrong_key_fails(monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "key-a")
    blob = encrypt_bytes(b"data")
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "key-b")
    with pytest.raises(Exception):
        decrypt_bytes(blob)


def test_low_level_decrypt_authenticates_ciphertext_not_manifest(monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "key")
    monkeypatch.setenv("SENTINEL_HMAC_KEY", "hmac-secret")
    blob = encrypt_bytes(b"x")
    assert decrypt_bytes(blob) == b"x"
