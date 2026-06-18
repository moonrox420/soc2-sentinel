import pytest

from sentinel.errors import ValidationError
from sentinel.validation import resolve_safe_output_base, sanitize_artifact_name


def test_output_base_not_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError, match="not a directory"):
        resolve_safe_output_base(f)


def test_artifact_empty_name():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("")