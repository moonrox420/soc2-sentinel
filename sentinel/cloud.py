from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

logger = logging.getLogger("sentinel")

T = TypeVar("T")

_DEFAULT_RETRYABLE = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "InternalError",
        "InternalServerError",
        "RequestTimeout",
    }
)


def botocore_config(*, connect_timeout: int = 10, read_timeout: int = 60, max_attempts: int = 3):
    from botocore.config import Config

    return Config(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={"max_attempts": max_attempts, "mode": "standard"},
    )


def is_retryable_error(exc: BaseException, *, retryable_codes: frozenset[str] | None = None) -> bool:
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    codes = retryable_codes or _DEFAULT_RETRYABLE
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code", "")
        if code in codes:
            return True
    name = exc.__class__.__name__
    return name in codes


def call_with_retry(
    fn: Callable[[], T],
    *,
    timeout: float | None = None,
    max_attempts: int = 3,
    retryable_codes: frozenset[str] | None = None,
    operation: str = "cloud_api",
) -> T:
    last_exc: BaseException | None = None
    for attempt in range(1, max_attempts + 1):
        started = time.monotonic()
        try:
            result = fn()
            elapsed_ms = int((time.monotonic() - started) * 1000)
            logger.debug("%s succeeded in %dms (attempt %d)", operation, elapsed_ms, attempt)
            return result
        except Exception as exc:
            last_exc = exc
            elapsed_ms = int((time.monotonic() - started) * 1000)
            retryable = is_retryable_error(exc, retryable_codes=retryable_codes)
            logger.warning(
                "%s failed in %dms (attempt %d/%d, retryable=%s): %s",
                operation,
                elapsed_ms,
                attempt,
                max_attempts,
                retryable,
                exc,
            )
            if not retryable or attempt >= max_attempts:
                raise
            time.sleep(min(2 ** attempt, 8))
    assert last_exc is not None
    raise last_exc


def snapshot_errors(*parts: str) -> dict[str, Any]:
    errors = [p for p in parts if p]
    return {"errors": errors, "partial": bool(errors)}