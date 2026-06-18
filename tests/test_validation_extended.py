import pytest

from sentinel.errors import ValidationError
from sentinel.validation import sanitize_artifact_name, sanitize_control_id


def test_control_id_reserved():
    with pytest.raises(ValidationError):
        sanitize_control_id("CON", strict_allowlist=False)


def test_artifact_invalid_format():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("bad name with spaces")


def test_control_id_empty():
    with pytest.raises(ValidationError):
        sanitize_control_id("", strict_allowlist=False)