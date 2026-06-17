import pytest

from sentinel.errors import ValidationError
from sentinel.validation import resolve_safe_output_base, sanitize_artifact_name, sanitize_control_id


def test_sanitize_control_id_rejects_traversal():
    with pytest.raises(ValidationError):
        sanitize_control_id("../etc/passwd")


def test_sanitize_control_id_accepts_known():
    assert sanitize_control_id("CC6.1") == "CC6.1"


def test_sanitize_artifact_name_rejects_parent():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("../report.json")


def test_resolve_safe_output_base_writable(tmp_path):
    resolved = resolve_safe_output_base(tmp_path)
    assert resolved == tmp_path.resolve()