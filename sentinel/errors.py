from __future__ import annotations

from typing import Any


class SentinelError(Exception):
    """Base error for SOC2 Sentinel."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.__class__.__name__, "message": self.message, "details": self.details}


class ValidationError(SentinelError):
    """Input or path validation failed."""


class ProviderError(SentinelError):
    """Cloud provider credential or API failure."""


class PartialEvidenceError(SentinelError):
    """Collection completed with partial data."""