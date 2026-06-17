from sentinel.security import encrypt_bytes, decrypt_bytes, redact_pii, sanitize_csv_cell


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