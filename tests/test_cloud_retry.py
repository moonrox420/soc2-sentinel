import pytest

from sentinel.cloud import call_with_retry


def test_call_with_retry_eventually_succeeds():
    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise ConnectionError("temporary")
        return "ok"

    assert call_with_retry(flaky, max_attempts=3, operation="test") == "ok"


def test_call_with_retry_non_retryable_raises():
    def fail() -> None:
        raise ValueError("bad input")

    with pytest.raises(ValueError):
        call_with_retry(fail, max_attempts=3, operation="test")