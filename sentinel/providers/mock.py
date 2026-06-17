from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.paths import install_root
from sentinel.providers.base import Provider

_FIXTURES = install_root() / "tests" / "fixtures"


class MockProvider(Provider):
    name = "mock"

    def _load(self, filename: str) -> dict[str, Any]:
        path = _FIXTURES / filename
        return json.loads(path.read_text(encoding="utf-8"))

    def iam_access_snapshot(self) -> dict[str, Any]:
        return self._load("iam_access.json")

    def log_monitoring_snapshot(self) -> dict[str, Any]:
        return self._load("log_monitoring.json")

    def config_and_auth_snapshot(self) -> dict[str, Any]:
        return self._load("config_auth.json")

    def encryption_snapshot(self) -> dict[str, Any]:
        return self._load("encryption.json")

    def retention_snapshot(self) -> dict[str, Any]:
        return self._load("retention.json")

    def resilience_snapshot(self) -> dict[str, Any]:
        return self._load("resilience.json")

    def zt_verification_snapshot(self) -> dict[str, Any]:
        return self._load("zt_verification.json")