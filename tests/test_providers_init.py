
from sentinel.config import SentinelConfig
from sentinel.providers import get_provider
from sentinel.providers.mock import MockProvider


def test_get_provider_mock():
    p = get_provider("mock", SentinelConfig())
    assert isinstance(p, MockProvider)


def test_get_provider_unknown():
    import pytest

    with pytest.raises(SystemExit):
        get_provider("unknown", SentinelConfig())