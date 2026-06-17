from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.errors import ProviderError
from sentinel.paths import install_root
from sentinel.providers.base import Provider

_FIXTURES = install_root() / "tests" / "fixtures"


class MockProvider(Provider):
    name = "mock"

    def validate_credentials(self) -> None:
        if not _FIXTURES.exists():
            raise ProviderError(
                f"Mock fixtures not found at {_FIXTURES}. "
                "Run from the toolkit root or re-extract the consumer zip."
            )

    def _load(self, filename: str) -> dict[str, Any]:
        path = _FIXTURES / filename
        if not path.exists():
            raise ProviderError(
                f"Missing mock fixture: {path.name}. Re-extract SOC2 Sentinel or run pip install -e ."
            )
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError(f"Invalid JSON in mock fixture {path.name}: {exc}") from exc

    def _with_meta(self, data: dict[str, Any]) -> dict[str, Any]:
        merged = dict(data)
        merged.setdefault("errors", [])
        merged.setdefault("partial", False)
        return merged

    def iam_access_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("iam_access.json"))

    def log_monitoring_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("log_monitoring.json"))

    def config_and_auth_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("config_auth.json"))

    def encryption_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("encryption.json"))

    def retention_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("retention.json"))

    def resilience_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("resilience.json"))

    def zt_verification_snapshot(self) -> dict[str, Any]:
        return self._with_meta(self._load("zt_verification.json"))