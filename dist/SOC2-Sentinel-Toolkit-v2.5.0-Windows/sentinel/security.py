from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path

from sentinel.errors import ValidationError

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_HEADER_V1 = b"SSENC1"
_HEADER_V2 = b"SSENC2"
_SALT_LEN = 16
_KEY_ID_LEN = 32


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
    return _EMAIL_RE.sub("[REDACTED_EMAIL]", text)


def sanitize_csv_cell(value: str | int | float | None) -> str:
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    if "\n" in text or "\r" in text:
        return '"' + text.replace('"', '""') + '"'
    return text


def _load_secret(secret: str | None = None) -> str:
    if secret:
        return secret
    key_file = os.environ.get("SENTINEL_EVIDENCE_KEY_FILE", "").strip()
    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip()
    return os.environ.get("SENTINEL_EVIDENCE_KEY", "").strip()


def _derive_key_v1(secret: str) -> bytes:
    return hashlib.sha256(f"sentinel-evidence-v1:{secret}".encode("utf-8")).digest()


def _derive_key_v2(secret: str, salt: bytes, key_id: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise ValidationError("cryptography package required for encryption") from exc
    info = f"sentinel-evidence-v2:{key_id}".encode("utf-8")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(
        secret.encode("utf-8")
    )


def _key_id() -> str:
    return os.environ.get("SENTINEL_EVIDENCE_KEY_ID", "default").strip() or "default"


def encrypt_bytes(data: bytes, *, secret: str | None = None) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ValidationError(
            "cryptography package required for encryption. pip install cryptography"
        ) from exc
    material = _load_secret(secret)
    if not material:
        raise ValidationError("encryption secret not configured")
    salt = os.urandom(_SALT_LEN)
    kid = _key_id().encode("utf-8")[:_KEY_ID_LEN]
    kid_padded = kid + b"\x00" * (_KEY_ID_LEN - len(kid))
    key = _derive_key_v2(material, salt, kid.decode("utf-8", errors="replace").rstrip("\x00"))
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, kid_padded)
    return _HEADER_V2 + salt + kid_padded + nonce + encrypted


def decrypt_bytes(
    blob: bytes,
    *,
    secret: str | None = None,
    manifest_hmac: str | None = None,
) -> bytes:
    hmac_key = os.environ.get("SENTINEL_HMAC_KEY", "").strip()
    if hmac_key and not manifest_hmac:
        raise ValidationError("decrypt requires manifest HMAC when SENTINEL_HMAC_KEY is set")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ValidationError("cryptography package required for decryption") from exc
    material = _load_secret(secret)
    if not material:
        raise ValidationError("decryption secret not configured")

    if blob.startswith(_HEADER_V2):
        salt = blob[6 : 6 + _SALT_LEN]
        kid_raw = blob[6 + _SALT_LEN : 6 + _SALT_LEN + _KEY_ID_LEN]
        kid = kid_raw.rstrip(b"\x00").decode("utf-8") or "default"
        nonce = blob[6 + _SALT_LEN + _KEY_ID_LEN : 6 + _SALT_LEN + _KEY_ID_LEN + 12]
        ciphertext = blob[6 + _SALT_LEN + _KEY_ID_LEN + 12 :]
        key = _derive_key_v2(material, salt, kid)
        return AESGCM(key).decrypt(nonce, ciphertext, kid_raw)

    if blob.startswith(_HEADER_V1):
        key = _derive_key_v1(material)
        nonce = blob[6:18]
        ciphertext = blob[18:]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    raise ValidationError("invalid encrypted blob header")


def verify_decrypt_hmac(expected_hmac: str, *, secret: str | None = None) -> None:
    """Enforce HMAC match before decrypt when SENTINEL_HMAC_KEY is set."""
    hmac_key = os.environ.get("SENTINEL_HMAC_KEY", "").strip()
    if not hmac_key:
        return
    if not expected_hmac:
        raise ValidationError("manifest HMAC required for decrypt when SENTINEL_HMAC_KEY is set")


def hmac_sign(content: bytes, *, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), content, hashlib.sha256).hexdigest()


def encryption_enabled(*, config_flag: bool = False) -> tuple[bool, str | None]:
    secret = _load_secret()
    if config_flag and secret:
        return True, secret
    if config_flag and not secret:
        raise ValidationError("evidence.encrypt is true but SENTINEL_EVIDENCE_KEY is not set")
    if secret:
        return True, secret
    return False, None


def encryption_header_version(blob: bytes) -> str:
    if blob.startswith(_HEADER_V2):
        return "v2"
    if blob.startswith(_HEADER_V1):
        return "v1"
    return "unknown"