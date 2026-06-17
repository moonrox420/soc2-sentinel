from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from pathlib import Path

from sentinel.errors import ValidationError

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_file_mode(path: Path, *, is_dir: bool = False) -> None:
    if os.name == "nt":
        return
    try:
        if is_dir:
            path.chmod(stat.S_IRWXU)
        else:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def redact_pii(text: str) -> str:
    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    return redacted


def sanitize_csv_cell(value: str | int | float | None) -> str:
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    if "\n" in text or "\r" in text:
        return '"' + text.replace('"', '""') + '"'
    return text


def _derive_key(secret: str, *, context: str) -> bytes:
    material = hashlib.sha256(f"{context}:{secret}".encode("utf-8")).digest()
    return material


def encrypt_bytes(data: bytes, *, secret: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ValidationError(
            "cryptography package required for encryption. pip install cryptography"
        ) from exc
    key = _derive_key(secret, context="sentinel-evidence-v1")
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    return b"SSENC1" + nonce + encrypted


def decrypt_bytes(blob: bytes, *, secret: str) -> bytes:
    if not blob.startswith(b"SSENC1"):
        raise ValidationError("invalid encrypted blob header")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ValidationError("cryptography package required for decryption") from exc
    key = _derive_key(secret, context="sentinel-evidence-v1")
    nonce = blob[6:18]
    ciphertext = blob[18:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def hmac_sign(content: bytes, *, secret: str) -> str:
    digest = hashlib.sha256(f"{secret}:".encode("utf-8") + content).hexdigest()
    return digest


def encryption_enabled(*, config_flag: bool = False) -> tuple[bool, str | None]:
    secret = os.environ.get("SENTINEL_EVIDENCE_KEY", "").strip()
    if config_flag and secret:
        return True, secret
    if config_flag and not secret:
        raise ValidationError("evidence.encrypt is true but SENTINEL_EVIDENCE_KEY is not set")
    if secret:
        return True, secret
    return False, None