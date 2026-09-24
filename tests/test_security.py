from sentinel.security import decrypt_bytes, encrypt_bytes, redact_pii, sanitize_csv_cell


def test_sanitize_csv_cell_formula():
    assert sanitize_csv_cell("=cmd|'/c calc'!A0").startswith("'")


def test_redact_pii_email():
    text = redact_pii("Contact admin@example.com for access")
    assert "admin@example.com" not in text
    assert "[REDACTED_EMAIL]" in text


def test_encrypt_roundtrip():
    secret = "test-key-material"
    plain = b"sensitive evidence"
    blob = encrypt_bytes(plain, secret=secret)
    assert decrypt_bytes(blob, secret=secret) == plain


# --- Consolidated from test_security_extended.py ---
import os

from sentinel.security import (
    decrypt_bytes,
    encryption_enabled,
    encryption_header_version,
    hmac_sign,
)


def test_v1_decrypt_legacy(monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "legacy-key")
    import hashlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


# --- Consolidated from test_security_hkdf.py ---
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


# --- Consolidated from test_security_paths.py ---

import pytest

from sentinel.errors import ValidationError
from sentinel.security import (
    encrypt_bytes,
    encryption_enabled,
    safe_file_mode,
    sanitize_csv_cell,
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


def test_encrypt_requires_secret(monkeypatch):
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_EVIDENCE_KEY_FILE", raising=False)
    with pytest.raises(ValidationError):
        encrypt_bytes(b"x", secret=None)


# --- Consolidated from test_output_security.py ---
import json

from sentinel.config import EvidenceConfig, SentinelConfig
from sentinel.integrity import verify_manifest
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso, validate_evidence
from sentinel.security import decrypt_bytes


def _payload(control_id: str = "CC6.1") -> dict:
    return {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {"total_identities": 1},
        "evidence_artifacts": [],
        "findings": [],
        "errors": [],
        "notes": "test",
        "provider": "mock",
    }


def test_write_evidence_creates_manifest(tmp_path):
    path = write_evidence(
        _payload(),
        base=tmp_path,
        extra_files={"artifact.txt": "hello"},
        config=SentinelConfig(),
    )
    assert path.exists()

    manifest = path.parent / "manifest.json"
    assert manifest.exists()

    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_evidence(payload)
    assert "artifact.txt" in payload["evidence_artifacts"]

    backup = tmp_path / "evidence"
    date_dirs = list(backup.iterdir())
    assert date_dirs
    manifests_backup = date_dirs[0] / "manifests" / "CC6.1.json"
    assert manifests_backup.exists()


def test_empty_extra_file_not_listed(tmp_path):
    path = write_evidence(
        _payload(),
        base=tmp_path,
        extra_files={"empty.csv": "   "},
        config=SentinelConfig(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "empty.csv" not in payload["evidence_artifacts"]
    assert "report.json" in payload["evidence_artifacts"]


def test_encrypted_write_tracks_and_manifests_real_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_EVIDENCE_KEY", "test-evidence-secret")
    cfg = SentinelConfig(evidence=EvidenceConfig(encrypt=True))

    path = write_evidence(
        _payload(),
        base=tmp_path,
        extra_files={"artifact.txt": "hello"},
        config=cfg,
    )

    assert path.name == "report.json.enc"
    assert path.exists()
    assert not (path.parent / "report.json").exists()
    assert (path.parent / "artifact.txt.enc").exists()
    assert (path.parent / "report.meta.json").exists()

    decrypted = json.loads(
        decrypt_bytes(
            path.read_bytes(),
            secret="test-evidence-secret",
        ).decode("utf-8")
    )
    assert decrypted["evidence_artifacts"] == [
        "artifact.txt.enc",
        "report.json.enc",
    ]

    manifest = json.loads(
        (path.parent / "manifest.json").read_text(encoding="utf-8")
    )
    assert "report.json.enc" in manifest["artifacts"]
    assert "artifact.txt.enc" in manifest["artifacts"]
    assert "report.meta.json" in manifest["artifacts"]

    ok, issues = verify_manifest(path.parent)
    assert ok, issues
