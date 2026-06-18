import pytest

from sentinel.errors import ValidationError
from sentinel.validation import sanitize_control_id


def test_unknown_control_rejected_by_default():
    with pytest.raises(ValidationError, match="not in known controls"):
        sanitize_control_id("CUSTOM-999", strict_allowlist=True)


def test_unknown_control_allowed_when_disabled():
    assert sanitize_control_id("CUSTOM-999", strict_allowlist=False) == "CUSTOM-999"


def test_known_control_passes():
    assert sanitize_control_id("CC6.1", strict_allowlist=True) == "CC6.1"