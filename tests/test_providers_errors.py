import pytest

from sentinel.errors import ProviderError
from sentinel.providers.mock import MockProvider


def test_mock_missing_fixture_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sentinel.providers.mock._FIXTURES",
        tmp_path / "missing-fixtures",
    )
    provider = MockProvider()
    with pytest.raises(ProviderError):
        provider.validate_credentials()